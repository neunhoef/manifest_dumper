# `manifest_dumper` - dump RocksDB MANIFEST files

This tool can dump the contents of a RocksDB MANIFEST file, even in the
case that the database uses customer comparators. This is where the standard
ldb tool seems to fail.
