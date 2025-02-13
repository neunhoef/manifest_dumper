use byteorder::{LittleEndian, ReadBytesExt};
use crc32c::crc32c;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;

const ZERO_TYPE: u8 = 0;
const FULL_TYPE: u8 = 1;
const FIRST_TYPE: u8 = 2;
const MIDDLE_TYPE: u8 = 3;
const LAST_TYPE: u8 = 4;

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

#[derive(Debug)]
struct InternalKey {
    data: Vec<u8>, // For now we just store raw bytes
}

#[derive(Debug)]
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
        }
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
}

#[derive(Debug)]
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

    fn read_record(&mut self) -> io::Result<Option<Vec<VersionEdit>>> {
        let mut whole_payload : Vec<u8> = Vec::new();
        loop {
            // Read the 7-byte header
            let mut header = [0u8; 7]; // 4 (crc) + 2 (size) + 1 (type)
            match self.reader.read_exact(&mut header) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }

            // Parse header
            let expected_crc = unmask_crc((&header[0..4]).read_u32::<LittleEndian>()?);
            let size = (&header[4..6]).read_u16::<LittleEndian>()? as usize;
            let record_type = header[6]; // Should be 1

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
                    "CRC mismatch: expected {:x}, got {:x}",
                    expected_crc, actual_crc
                );
            }
            match record_type {
                FULL_TYPE => {
                    whole_payload = payload;
                    break;
                },
                FIRST_TYPE => {
                    whole_payload = payload;
                },
                MIDDLE_TYPE => {
                    whole_payload.extend_from_slice(&payload);
                },
                LAST_TYPE => {
                    whole_payload.extend_from_slice(&payload);
                    break;
                },
                ZERO_TYPE | _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unexpected record type: {}", record_type),
                    ));
                },
            }
        }

        // Create a cursor to read from the payload
        let size = whole_payload.len();
        let mut cursor = std::io::Cursor::new(whole_payload);
        let mut edits = Vec::new();

        // Read all items from the payload
        while cursor.position() < size as u64 {
            let tag = read_varint32(&mut cursor)?;
            match tag {
                1 => {
                    // kComparator
                    let data = read_length_prefixed_slice(&mut cursor)?;
                    let comparator = String::from_utf8(data)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    edits.push(VersionEdit::Comparator(comparator));
                }
                2 => {
                    // kLogNumber
                    let log_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::LogNumber(log_number));
                }
                3 => {
                    // kNextFileNumber
                    let next_file_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::NextFileNumber(next_file_number));
                }
                4 => {
                    // kLastSequence
                    let last_sequence = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::LastSequence(last_sequence));
                }
                103 => {
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
                        match custom_tag {
                            2 => {
                                // kNeedCompaction
                                if field_data.len() != 1 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "need_compaction field wrong size",
                                    ));
                                }
                                meta.needs_compaction = field_data[0] == 1;
                            }
                            3 => {
                                // kMinLogNumberToKeepHack
                                let mut field_cursor = Cursor::new(field_data);
                                meta.min_log_number_to_keep =
                                    Some(field_cursor.read_u64::<LittleEndian>()?);
                            }
                            4 => {
                                // kOldestBlobFileNumber
                                let mut field_cursor = Cursor::new(field_data);
                                meta.oldest_blob_file_number =
                                    Some(read_varint64(&mut field_cursor)?);
                            }
                            5 => {
                                // kOldestAncesterTime
                                let mut field_cursor = Cursor::new(field_data);
                                meta.oldest_ancester_time = read_varint64(&mut field_cursor)?;
                            }
                            6 => {
                                // kFileCreationTime
                                let mut field_cursor = Cursor::new(field_data);
                                meta.file_creation_time = read_varint64(&mut field_cursor)?;
                            }
                            7 => {
                                // kFileChecksum
                                meta.file_checksum = String::from_utf8(field_data)
                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                            }
                            8 => {
                                // kFileChecksumFuncName
                                meta.file_checksum_func_name = String::from_utf8(field_data)
                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                            }
                            9 => {
                                // kTemperature
                                if field_data.len() != 1 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "temperature field wrong size",
                                    ));
                                }
                                meta.temperature = Some(field_data[0]);
                            }
                            12 => {
                                // kUniqueId
                                meta.unique_id = field_data;
                            }
                            13 => {
                                // kEpochNumber
                                let mut field_cursor = Cursor::new(field_data);
                                meta.epoch_number = read_varint64(&mut field_cursor)?;
                            }
                            14 => {
                                // kCompensatedRangeDeletionSize
                                let mut field_cursor = Cursor::new(field_data);
                                meta.compensated_range_deletion_size =
                                    read_varint64(&mut field_cursor)?;
                            }
                            15 => {
                                // kTailSize
                                let mut field_cursor = Cursor::new(field_data);
                                meta.tail_size = read_varint64(&mut field_cursor)?;
                            }
                            16 => {
                                // kUserDefinedTimestampsPersisted
                                if field_data.len() != 1 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "user-defined timestamps persisted field wrong size",
                                    ));
                                }
                                meta.user_defined_timestamps_persisted = field_data[0] == 1;
                            }
                            _ => {
                                if (custom_tag & 0x40) != 0 {
                                    // kCustomTagNonSafeIgnoreMask
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "new-file4 custom field not supported",
                                    ));
                                }
                                // Safe to ignore this tag
                            }
                        }
                    }
                    edits.push(VersionEdit::NewFile4(meta));
                }
                200 => {
                    // kColumnFamily
                    let column_family = read_varint32(&mut cursor)?;
                    edits.push(VersionEdit::ColumnFamily(column_family));
                }
                201 => {
                    // kColumnFamilyAdd
                    let data = read_length_prefixed_slice(&mut cursor)?;
                    let column_family_name = String::from_utf8(data)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    edits.push(VersionEdit::ColumnFamilyAdd(column_family_name));
                }
                9 => {
                    // kPrevLogNumber
                    let prev_log_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::PrevLogNumber(prev_log_number));
                }
                203 => {
                    // kMaxColumnFamily
                    let max_column_family = read_varint32(&mut cursor)?;
                    edits.push(VersionEdit::MaxColumnFamily(max_column_family));
                }
                6 => {
                    // kDeletedFile
                    let level = read_varint32(&mut cursor)?;
                    let file_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::DeletedFile(level, file_number));
                }
                5 => {
                    // kCompactCursor
                    let level = read_varint32(&mut cursor)?;
                    let cursor_data = read_length_prefixed_slice(&mut cursor)?;
                    edits.push(VersionEdit::CompactCursor(
                        level,
                        InternalKey { data: cursor_data },
                    ));
                }
                10 => {
                    // kMinLogNumberToKeep
                    let min_log_number = read_varint64(&mut cursor)?;
                    edits.push(VersionEdit::MinLogNumberToKeep(min_log_number));
                }
                202 => {
                    // kColumnFamilyDrop
                    edits.push(VersionEdit::ColumnFamilyDrop);
                }
                // ... handle other tags
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unknown tag: {}", tag),
                    ));
                }
            }
        }

        Ok(Some(edits))
    }
}

fn main() -> io::Result<()> {
    let manifest_path = std::env::args()
        .nth(1)
        .expect("Please provide path to MANIFEST file");

    let mut reader = ManifestReader::new(manifest_path)?;

    while let Some(edit) = reader.read_record()? {
        println!("{:?}", edit);
    }

    Ok(())
}
