use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, TimeZone, Utc};
use crc32c::crc32c;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Seek};
use std::path::Path;

const ZERO_TYPE: u8 = 0;
const FULL_TYPE: u8 = 1;
const FIRST_TYPE: u8 = 2;
const MIDDLE_TYPE: u8 = 3;
const LAST_TYPE: u8 = 4;

const BLOCK_SIZE: u64 = 0x8000;
const HEADER_SIZE: u64 = 7;

#[derive(Debug)]
enum Tag {
    Comparator = 1,
    LogNumber = 2,
    NextFileNumber = 3,
    LastSequence = 4,
    CompactCursor = 5,
    DeletedFile = 6,
    NewFile = 7,
    PrevLogNumber = 9,
    MinLogNumberToKeep = 10,
    // RocksDB-specific formats
    NewFile2 = 100,
    NewFile3 = 102,
    NewFile4 = 103, // Latest format for adding files
    ColumnFamily = 200,
    ColumnFamilyAdd = 201,
    ColumnFamilyDrop = 202,
    MaxColumnFamily = 203,
    // ... other tags can be added as needed
}

impl TryFrom<u8> for Tag {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Tag::Comparator),
            2 => Ok(Tag::LogNumber),
            3 => Ok(Tag::NextFileNumber),
            4 => Ok(Tag::LastSequence),
            5 => Ok(Tag::CompactCursor),
            6 => Ok(Tag::DeletedFile),
            7 => Ok(Tag::NewFile),
            9 => Ok(Tag::PrevLogNumber),
            10 => Ok(Tag::MinLogNumberToKeep),
            100 => Ok(Tag::NewFile2),
            102 => Ok(Tag::NewFile3),
            103 => Ok(Tag::NewFile4),
            200 => Ok(Tag::ColumnFamily),
            201 => Ok(Tag::ColumnFamilyAdd),
            202 => Ok(Tag::ColumnFamilyDrop),
            203 => Ok(Tag::MaxColumnFamily),
            _ => Err("Invalid tag value"),
        }
    }
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> u8 {
        tag as u8
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct InternalKey {
    data: Vec<u8>, // For now we just store raw bytes
}

impl fmt::Display for InternalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.data {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, " ")?;
        for byte in &self.data {
            if byte.is_ascii_alphanumeric() {
                write!(f, "{}", *byte as char)?;
            } else {
                write!(f, ".")?;
            }
        }
        write!(f, "")
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FileMetaData {
    level: u32,
    file_number: u64,
    file_size: u64,
    smallest_key: InternalKey,
    largest_key: InternalKey,
    smallest_seqno: u64,
    largest_seqno: u64,
    // Custom fields
    path_id: u32,
    needs_compaction: bool,
    min_log_number_to_keep: Option<u64>,
    oldest_blob_file_number: Option<u64>,
    oldest_ancester_time: u64,
    file_creation_time: u64,
    epoch_number: u64,
    file_checksum: String,
    file_checksum_func_name: String,
    temperature: Option<u8>,
    unique_id: Vec<u8>, // For now store as raw bytes
    compensated_range_deletion_size: u64,
    tail_size: u64,
    user_defined_timestamps_persisted: bool,
    min_timestamp: Option<Vec<u8>>, // Store as raw bytes
    max_timestamp: Option<Vec<u8>>, // Store as raw bytes
    deleted: bool,
}

impl Default for FileMetaData {
    fn default() -> Self {
        Self {
            level: 0,
            file_number: 0,
            file_size: 0,
            smallest_key: InternalKey { data: Vec::new() },
            largest_key: InternalKey { data: Vec::new() },
            smallest_seqno: 0,
            largest_seqno: 0,
            path_id: 0,
            needs_compaction: false,
            min_log_number_to_keep: None,
            oldest_blob_file_number: None,
            oldest_ancester_time: 0,
            file_creation_time: 0,
            epoch_number: 0,
            file_checksum: String::new(),
            file_checksum_func_name: String::new(),
            temperature: None,
            unique_id: Vec::new(),
            compensated_range_deletion_size: 0,
            tail_size: 0,
            user_defined_timestamps_persisted: true, // Default is true
            min_timestamp: None,
            max_timestamp: None,
            deleted: false,
        }
    }
}

impl fmt::Display for FileMetaData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "FileMetaData {{")?;
        writeln!(f, "  level: {}", self.level)?;
        writeln!(f, "  file: {}", self.file_number)?;
        writeln!(f, "  size: {}", self.file_size)?;
        writeln!(f, "  smallest_key: {}", self.smallest_key)?;
        writeln!(f, "  largest_key : {}", self.largest_key)?;
        writeln!(
            f,
            "  seqno: {}..{}",
            self.smallest_seqno, self.largest_seqno
        )?;

        if self.path_id != 0 {
            writeln!(f, "  path_id: {}", self.path_id)?;
        }
        if self.needs_compaction {
            writeln!(f, "  needs_compaction: true")?;
        }
        if let Some(num) = self.min_log_number_to_keep {
            writeln!(f, "  min_log_number_to_keep: {}", num)?;
        }
        if let Some(num) = self.oldest_blob_file_number {
            writeln!(f, "  oldest_blob_file: {}", num)?;
        }
        if self.oldest_ancester_time != 0 {
            let dt: DateTime<Utc> = Utc
                .timestamp_opt(self.oldest_ancester_time as i64, 0)
                .unwrap();
            writeln!(
                f,
                "  oldest_ancester_time: {}",
                dt.format("%Y-%m-%d %H:%M:%S UTC")
            )?;
        }
        if self.file_creation_time != 0 {
            let dt: DateTime<Utc> = Utc
                .timestamp_opt(self.file_creation_time as i64, 0)
                .unwrap();
            writeln!(
                f,
                "  file_creation_time: {}",
                dt.format("%Y-%m-%d %H:%M:%S UTC")
            )?;
        }
        if self.epoch_number != 0 {
            writeln!(f, "  epoch_number: {}", self.epoch_number)?;
        }
        if !self.file_checksum.is_empty() {
            writeln!(f, "  checksum: {}", self.file_checksum)?;
            writeln!(f, "  checksum_func: {}", self.file_checksum_func_name)?;
        }
        if let Some(temp) = self.temperature {
            writeln!(f, "  temperature: {}", temp)?;
        }
        if !self.unique_id.is_empty() {
            writeln!(f, "  unique_id: {:?}", self.unique_id)?;
        }
        if self.compensated_range_deletion_size != 0 {
            writeln!(
                f,
                "  compensated_range_deletion_size: {}",
                self.compensated_range_deletion_size
            )?;
        }
        if self.tail_size != 0 {
            writeln!(f, "  tail_size: {}", self.tail_size)?;
        }
        if !self.user_defined_timestamps_persisted {
            writeln!(f, "  user_defined_timestamps_persisted: false")?;
        }
        if let Some(ref ts) = self.min_timestamp {
            writeln!(f, "  min_timestamp: {:?}", ts)?;
        }
        if let Some(ref ts) = self.max_timestamp {
            writeln!(f, "  max_timestamp: {:?}", ts)?;
        }
        if self.deleted {
            writeln!(f, "  deleted: true")?;
        }
        write!(f, "}}")
    }
}

enum NewFileCustomTag {
    Terminate = 1,
    NeedCompaction = 2,
    MinLogNumberToKeepHack = 3,
    OldestBlobFileNumber = 4,
    OldestAncesterTime = 5,
    FileCreationTime = 6,
    FileChecksum = 7,
    FileChecksumFuncName = 8,
    Temperature = 9,
    MinTimestamp = 10,
    MaxTimestamp = 11,
    UniqueId = 12,
    EpochNumber = 13,
    CompensateRangeDeletionSize = 14,
    TailSize = 15,
    UserDefinedTimestampsPersisted = 16,
}

impl TryFrom<u32> for NewFileCustomTag {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(NewFileCustomTag::Terminate),
            2 => Ok(NewFileCustomTag::NeedCompaction),
            3 => Ok(NewFileCustomTag::MinLogNumberToKeepHack),
            4 => Ok(NewFileCustomTag::OldestBlobFileNumber),
            5 => Ok(NewFileCustomTag::OldestAncesterTime),
            6 => Ok(NewFileCustomTag::FileCreationTime),
            7 => Ok(NewFileCustomTag::FileChecksum),
            8 => Ok(NewFileCustomTag::FileChecksumFuncName),
            9 => Ok(NewFileCustomTag::Temperature),
            10 => Ok(NewFileCustomTag::MinTimestamp),
            11 => Ok(NewFileCustomTag::MaxTimestamp),
            12 => Ok(NewFileCustomTag::UniqueId),
            13 => Ok(NewFileCustomTag::EpochNumber),
            14 => Ok(NewFileCustomTag::CompensateRangeDeletionSize),
            15 => Ok(NewFileCustomTag::TailSize),
            16 => Ok(NewFileCustomTag::UserDefinedTimestampsPersisted),
            _ => Err("Invalid NewFileCustomTag value"),
        }
    }
}

impl From<NewFileCustomTag> for u32 {
    fn from(tag: NewFileCustomTag) -> u32 {
        tag as u32
    }
}
#[derive(Debug)]
#[allow(dead_code)]
enum VersionEdit {
    Comparator(String),
    LogNumber(u64),
    NextFileNumber(u64),
    LastSequence(u64),
    NewFile4(FileMetaData),
    ColumnFamily(u32),
    ColumnFamilyAdd(String),
    PrevLogNumber(u64),
    MaxColumnFamily(u32),
    DeletedFile(u32, u64),           // (level, file_number)
    CompactCursor(u32, InternalKey), // (level, cursor)
    MinLogNumberToKeep(u64),
    ColumnFamilyDrop, // no additional data needed
                      // ... other variants as needed
}

impl fmt::Display for VersionEdit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionEdit::Comparator(name) => {
                write!(f, "Comparator: {}", name)
            }
            VersionEdit::LogNumber(num) => {
                write!(f, "LogNumber: {}", num)
            }
            VersionEdit::NextFileNumber(num) => {
                write!(f, "NextFileNumber: {}", num)
            }
            VersionEdit::LastSequence(seq) => {
                write!(f, "LastSequence: {}", seq)
            }
            VersionEdit::NewFile4(meta) => {
                writeln!(f, "NewFile4 {{")?;
                write!(f, "{}", meta)?;
                write!(f, "}}")
            }
            VersionEdit::ColumnFamily(id) => {
                write!(f, "ColumnFamily: {}", id)
            }
            VersionEdit::ColumnFamilyAdd(name) => {
                write!(f, "ColumnFamilyAdd: {}", name)
            }
            VersionEdit::PrevLogNumber(num) => {
                write!(f, "PrevLogNumber: {}", num)
            }
            VersionEdit::MaxColumnFamily(num) => {
                write!(f, "MaxColumnFamily: {}", num)
            }
            VersionEdit::DeletedFile(level, file_number) => {
                write!(f, "DeletedFile: level {} file {}", level, file_number)
            }
            VersionEdit::CompactCursor(level, key) => {
                write!(f, "CompactCursor: level {} key {}", level, key)
            }
            VersionEdit::MinLogNumberToKeep(num) => {
                write!(f, "MinLogNumberToKeep: {}", num)
            }
            VersionEdit::ColumnFamilyDrop => {
                write!(f, "ColumnFamilyDrop")
            }
        }
    }
}

struct ManifestReader {
    reader: BufReader<File>,
}

fn read_varint32(cursor: &mut Cursor<Vec<u8>>) -> io::Result<u32> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf)?;
        let byte = buf[0] as u32;
        result |= (byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

fn read_varint64(cursor: &mut Cursor<Vec<u8>>) -> io::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf)?;
        let byte = buf[0] as u64;
        result |= (byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

fn read_length_prefixed_slice(cursor: &mut Cursor<Vec<u8>>) -> io::Result<Vec<u8>> {
    let length = read_varint32(cursor)? as usize;
    let mut data = vec![0u8; length];
    cursor.read_exact(&mut data)?;
    Ok(data)
}

fn unmask_crc(c: u32) -> u32 {
    let rot = c.wrapping_sub(0xa282ead8u32);
    (rot >> 17) | (rot << 15)
}

impl ManifestReader {
    fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        Ok(ManifestReader {
            reader: BufReader::new(file),
        })
    }

    fn position(&mut self) -> u64 {
        self.reader.stream_position().unwrap()
    }

    fn read_record(&mut self) -> io::Result<Option<Vec<VersionEdit>>> {
        let mut whole_payload: Vec<u8> = Vec::new();
        loop {
            let mut left_in_block =
                BLOCK_SIZE - (self.reader.stream_position().unwrap() % BLOCK_SIZE);
            if left_in_block < HEADER_SIZE {
                let mut buf = vec![0u8; left_in_block as usize];
                let _ = self.reader.read_exact(&mut buf);
                left_in_block = BLOCK_SIZE;
            }

            // Read the 7-byte header
            let mut header = [0u8; 7]; // 4 (crc) + 2 (size) + 1 (type)
            match self.reader.read_exact(&mut header) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }

            // Parse header
            let mut expected_crc = (&header[0..4]).read_u32::<LittleEndian>()?;
            let size = (&header[4..6]).read_u16::<LittleEndian>()? as usize;
            let record_type = header[6]; // Should be 1

            // All zero?
            if expected_crc == 0 && size == 0 && record_type == 0 {
                let mut buf = vec![0u8; left_in_block as usize];
                let _ = self.reader.read_exact(&mut buf);
            }

            expected_crc = unmask_crc(expected_crc);
            // Read the payload
            let mut payload = vec![0u8; size];
            self.reader.read_exact(&mut payload)?;

            // Verify CRC
            // Create data for CRC calculation: type byte + payload
            let mut data_for_crc = Vec::with_capacity(1 + size);
            data_for_crc.push(record_type); // The type byte
            data_for_crc.extend_from_slice(&payload);
            let actual_crc = crc32c(&data_for_crc);

            if actual_crc != expected_crc {
                eprintln!(
                    "CRC mismatch: expected {:x}, got {:x}, current offset in file: {}, size of last payload: {}",
                    expected_crc, actual_crc, self.reader.stream_position().unwrap(),
                    size,
                );
            }
            match record_type {
                FULL_TYPE => {
                    whole_payload = payload;
                    break;
                }
                FIRST_TYPE => {
                    whole_payload = payload;
                }
                MIDDLE_TYPE => {
                    whole_payload.extend_from_slice(&payload);
                }
                LAST_TYPE => {
                    whole_payload.extend_from_slice(&payload);
                    break;
                }
                ZERO_TYPE | _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unexpected record type: {}", record_type),
                    ));
                }
            }
        }

        // Create a cursor to read from the payload
        let size = whole_payload.len();
        let mut cursor = std::io::Cursor::new(whole_payload);
        let mut edits = Vec::new();

        // Read all items from the payload
        while cursor.position() < size as u64 {
            let tag = read_varint32(&mut cursor)?;
            match Tag::try_from(tag as u8) {
                Ok(Tag::Comparator) => {
                    // kComparator
                    let data = read_length_prefixed_slice(&mut cursor)?;
                    let comparator = String::from_utf8(data)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    edits.push(VersionEdit::Comparator(comparator));
                }
                Ok(Tag::LogNumber) => {
                    // kLogNumber
                    let log_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::LogNumber(log_number));
                }
                Ok(Tag::NextFileNumber) => {
                    // kNextFileNumber
                    let next_file_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::NextFileNumber(next_file_number));
                }
                Ok(Tag::LastSequence) => {
                    // kLastSequence
                    let last_sequence = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::LastSequence(last_sequence));
                }
                Ok(Tag::NewFile) | Ok(Tag::NewFile2) | Ok(Tag::NewFile3) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Obsolete tag: {}", tag),
                    ));
                }
                Ok(Tag::NewFile4) => {
                    // kNewFile4
                    let level = read_varint32(&mut cursor)?;
                    let file_number = read_varint64(&mut cursor)?;
                    let file_size = read_varint64(&mut cursor)?;

                    let smallest_key_data = read_length_prefixed_slice(&mut cursor)?;
                    let largest_key_data = read_length_prefixed_slice(&mut cursor)?;

                    let smallest_seqno = read_varint64(&mut cursor)?;
                    let largest_seqno = read_varint64(&mut cursor)?;

                    let mut meta = FileMetaData::default();
                    meta.level = level;
                    meta.file_number = file_number;
                    meta.file_size = file_size;
                    meta.smallest_key = InternalKey {
                        data: smallest_key_data,
                    };
                    meta.largest_key = InternalKey {
                        data: largest_key_data,
                    };
                    meta.smallest_seqno = smallest_seqno;
                    meta.largest_seqno = largest_seqno;

                    // Read custom fields until terminating tag
                    loop {
                        let custom_tag = read_varint32(&mut cursor)?;
                        if custom_tag == NewFileCustomTag::Terminate as u32 {
                            break;
                        }

                        let field_data = read_length_prefixed_slice(&mut cursor)?;
                        match NewFileCustomTag::try_from(custom_tag) {
                            Ok(NewFileCustomTag::Terminate) => {
                                // kTerminate
                                break;
                            }
                            Ok(NewFileCustomTag::NeedCompaction) => {
                                // kNeedCompaction
                                if field_data.len() != 1 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "need_compaction field wrong size",
                                    ));
                                }
                                meta.needs_compaction = field_data[0] == 1;
                            }
                            Ok(NewFileCustomTag::MinLogNumberToKeepHack) => {
                                // kMinLogNumberToKeepHack
                                let mut field_cursor = Cursor::new(field_data);
                                meta.min_log_number_to_keep =
                                    Some(field_cursor.read_u64::<LittleEndian>()?);
                            }
                            Ok(NewFileCustomTag::OldestBlobFileNumber) => {
                                // kOldestBlobFileNumber
                                let mut field_cursor = Cursor::new(field_data);
                                meta.oldest_blob_file_number =
                                    Some(read_varint64(&mut field_cursor)?);
                            }
                            Ok(NewFileCustomTag::OldestAncesterTime) => {
                                // kOldestAncesterTime
                                let mut field_cursor = Cursor::new(field_data);
                                meta.oldest_ancester_time = read_varint64(&mut field_cursor)?;
                            }
                            Ok(NewFileCustomTag::FileCreationTime) => {
                                // kFileCreationTime
                                let mut field_cursor = Cursor::new(field_data);
                                meta.file_creation_time = read_varint64(&mut field_cursor)?;
                            }
                            Ok(NewFileCustomTag::FileChecksum) => {
                                // kFileChecksum
                                meta.file_checksum = String::from_utf8(field_data)
                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                            }
                            Ok(NewFileCustomTag::FileChecksumFuncName) => {
                                // kFileChecksumFuncName
                                meta.file_checksum_func_name = String::from_utf8(field_data)
                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                            }
                            Ok(NewFileCustomTag::Temperature) => {
                                // kTemperature
                                if field_data.len() != 1 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "temperature field wrong size",
                                    ));
                                }
                                meta.temperature = Some(field_data[0]);
                            }
                            Ok(NewFileCustomTag::UniqueId) => {
                                // kUniqueId
                                meta.unique_id = field_data;
                            }
                            Ok(NewFileCustomTag::EpochNumber) => {
                                // kEpochNumber
                                let mut field_cursor = Cursor::new(field_data);
                                meta.epoch_number = read_varint64(&mut field_cursor)?;
                            }
                            Ok(NewFileCustomTag::CompensateRangeDeletionSize) => {
                                // kCompensatedRangeDeletionSize
                                let mut field_cursor = Cursor::new(field_data);
                                meta.compensated_range_deletion_size =
                                    read_varint64(&mut field_cursor)?;
                            }
                            Ok(NewFileCustomTag::TailSize) => {
                                // kTailSize
                                let mut field_cursor = Cursor::new(field_data);
                                meta.tail_size = read_varint64(&mut field_cursor)?;
                            }
                            Ok(NewFileCustomTag::UserDefinedTimestampsPersisted) => {
                                // kUserDefinedTimestampsPersisted
                                if field_data.len() != 1 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "user-defined timestamps persisted field wrong size",
                                    ));
                                }
                                meta.user_defined_timestamps_persisted = field_data[0] == 1;
                            }
                            Ok(NewFileCustomTag::MinTimestamp) => {
                                meta.min_timestamp = Some(field_data);
                            }
                            Ok(NewFileCustomTag::MaxTimestamp) => {
                                meta.max_timestamp = Some(field_data);
                            }
                            Err(err) => {
                                if (custom_tag & 0x40) != 0 {
                                    // kCustomTagNonSafeIgnoreMask
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "new-file4 custom field not supported: {} {}",
                                            custom_tag, err
                                        ),
                                    ));
                                }
                                // Safe to ignore this tag
                            }
                        }
                    }
                    edits.push(VersionEdit::NewFile4(meta));
                }
                Ok(Tag::ColumnFamily) => {
                    // kColumnFamily
                    let column_family = read_varint32(&mut cursor)?;
                    edits.push(VersionEdit::ColumnFamily(column_family));
                }
                Ok(Tag::ColumnFamilyAdd) => {
                    // kColumnFamilyAdd
                    let data = read_length_prefixed_slice(&mut cursor)?;
                    let column_family_name = String::from_utf8(data)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    edits.push(VersionEdit::ColumnFamilyAdd(column_family_name));
                }
                Ok(Tag::PrevLogNumber) => {
                    // kPrevLogNumber
                    let prev_log_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::PrevLogNumber(prev_log_number));
                }
                Ok(Tag::MaxColumnFamily) => {
                    // kMaxColumnFamily
                    let max_column_family = read_varint32(&mut cursor)?;
                    edits.push(VersionEdit::MaxColumnFamily(max_column_family));
                }
                Ok(Tag::DeletedFile) => {
                    // kDeletedFile
                    let level = read_varint32(&mut cursor)?;
                    let file_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::DeletedFile(level, file_number));
                }
                Ok(Tag::CompactCursor) => {
                    // kCompactCursor
                    let level = read_varint32(&mut cursor)?;
                    let cursor_data = read_length_prefixed_slice(&mut cursor)?;
                    edits.push(VersionEdit::CompactCursor(
                        level,
                        InternalKey { data: cursor_data },
                    ));
                }
                Ok(Tag::MinLogNumberToKeep) => {
                    // kMinLogNumberToKeep
                    let min_log_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::MinLogNumberToKeep(min_log_number));
                }
                Ok(Tag::ColumnFamilyDrop) => {
                    // kColumnFamilyDrop
                    edits.push(VersionEdit::ColumnFamilyDrop);
                }
                // ... handle other tags
                Err(err) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unknown tag: {} {}", tag, err),
                    ));
                }
            }
        }

        Ok(Some(edits))
    }
}

struct CompactionInfo {
    start_position: usize,  // Position in all_edits where this compaction starts
    prev_log_number: u64,
    next_file_number: u64,
    last_sequence: u64,
    deleted_files: Vec<(u32, u64)>,  // (level, file_number)
    new_files: Vec<FileMetaData>,
    column_family: u32,
}

impl fmt::Display for CompactionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Compaction at position {} {{", self.start_position)?;
        writeln!(f, "  PrevLogNumber: {}", self.prev_log_number)?;
        writeln!(f, "  NextFileNumber: {}", self.next_file_number)?;
        writeln!(f, "  LastSequence: {}", self.last_sequence)?;
        writeln!(f, "  Deleted files:")?;
        for (level, file) in &self.deleted_files {
            writeln!(f, "    Level {}: File {}", level, file)?;
        }
        writeln!(f, "  New files:")?;
        for file in &self.new_files {
            writeln!(f, "    {}", file)?;
        }
        writeln!(f, "  ColumnFamily: {}", self.column_family)?;
        write!(f, "}}")
    }
}

fn find_compactions(all_edits: &Vec<Vec<VersionEdit>>) -> Vec<CompactionInfo> {
    let mut compactions = Vec::new();
    
    for (position, edits) in all_edits.iter().enumerate() {
        // Need at least 4 edits for a minimal compaction pattern
        if edits.len() < 4 {
            continue;
        }
        
        // Check if this could be the start of a compaction pattern
        let mut iter = edits.iter().enumerate();
        
        // Try to match the pattern
        let mut current_compaction = None;
        
        while let Some((i, edit)) = iter.next() {
            match edit {
                // Start of potential compaction pattern
                VersionEdit::PrevLogNumber(log_num) => {
                    // Look ahead for required sequence
                    if let Some(next_file) = edits.get(i + 1) {
                        if let Some(last_seq) = edits.get(i + 2) {
                            match (next_file, last_seq) {
                                (
                                    VersionEdit::NextFileNumber(next_num),
                                    VersionEdit::LastSequence(seq)
                                ) => {
                                    current_compaction = Some(CompactionInfo {
                                        start_position: position,
                                        prev_log_number: *log_num,
                                        next_file_number: *next_num,
                                        last_sequence: *seq,
                                        deleted_files: Vec::new(),
                                        new_files: Vec::new(),
                                        column_family: 0, // Will be set later
                                    });
                                    // Skip the next two entries as we've processed them
                                    iter.next();
                                    iter.next();
                                }
                                _ => {
                                    current_compaction = None;
                                }
                            }
                        }
                    }
                }
                
                // Collect deleted files if we're in a compaction
                VersionEdit::DeletedFile(level, file_num) => {
                    if let Some(ref mut compaction) = current_compaction {
                        compaction.deleted_files.push((*level, *file_num));
                    }
                }
                
                // Collect new files if we're in a compaction
                VersionEdit::NewFile4(meta) => {
                    if let Some(ref mut compaction) = current_compaction {
                        compaction.new_files.push(meta.clone());
                    }
                }
                
                // End of compaction pattern
                VersionEdit::ColumnFamily(cf_id) => {
                    if let Some(mut compaction) = current_compaction.take() {
                        compaction.column_family = *cf_id;
                        // Validate that this looks like a real compaction
                        if !compaction.deleted_files.is_empty() && !compaction.new_files.is_empty() {
                            compactions.push(compaction);
                        }
                    }
                }
                
                _ => {}
            }
        }
    }
    
    compactions
}

fn main() -> io::Result<()> {
    let manifest_path = std::env::args()
        .nth(1)
        .expect("Please provide path to MANIFEST file");

    let mut reader = ManifestReader::new(manifest_path)?;

    let mut files: HashMap<u64, FileMetaData> = HashMap::new();

    let mut pos: u64 = 0;
    let mut all_edits : Vec<Vec<VersionEdit>> = Vec::new();
    while let Some(edit) = reader.read_record()? {
        let newpos = reader.position();
        println!("New edits: {:x} {:x}", pos, newpos - pos);
        pos = newpos;

        for e in &edit {
            println!("  {}", e);
            match e {
                VersionEdit::NewFile4(meta) => {
                    files.insert(meta.file_number, meta.clone());
                }
                VersionEdit::DeletedFile(_level, file_number) => {
                    let file = files.get_mut(&file_number);
                    match file {
                        Some(meta) => {
                            meta.deleted = true;
                        }
                        None => {
                            println!("File {} not found for deletion", file_number);
                        }
                    }
                }
                _ => {}
            }
        }
        all_edits.push(edit);
    }

    // Now print out the list of files:
    println!("List of data files:");
    let mut v : Vec<FileMetaData> = Vec::with_capacity(files.len());
    for (_nr, meta) in files {
        v.push(meta.clone());
    }
    v.sort_by(|a, b| a.file_number.cmp(&b.file_number));
    for (i, meta) in v.iter().enumerate() {
        println!("File #{}: {}", i, meta);
    }
    // Find and print compactions:
    let compactions = find_compactions(&all_edits);
    println!("\nFound {} potential compactions:", compactions.len());
    for (i, compaction) in compactions.iter().enumerate() {
        println!("\nCompaction #{}", i + 1);
        println!("{}", compaction);
    }
    Ok(())
}

// Add this to your main function:
