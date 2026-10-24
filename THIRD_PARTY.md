# Bundled source provenance

| Component | Repository | Pinned commit |
| --- | --- | --- |
| HttpdWin | https://github.com/CsmcWzrd/httpdwin | def06d5921da28d3c7156e2864ae9b7fd217c522 |
| Zar | https://github.com/CsmcWzrd/Zar | c8920b771b249632f059e918d0c77c32bf3a96e0 |

Both are compiled directly from `third_party` without fetching dependencies.
HttpdWin changes are documented in its bundled README. All original copyright
notices remain. Its pinned repository has no standalone license file.
Zar's MIT license is preserved in `third_party/Zar/LICENSE`.

Zar changes: `readBinary` extracts a checksum-verified binary record without
JSON export. `openSnapshot` strictly reads one bounded, read-only record
without automatic index repair. DocSecWin uses these for its snapshot format.
General Zar APIs remain included. Zar's extraction and temporary JSON export
APIs are not exposed by HTTP. The payload format is in docs/STORAGE.md.
OpenSSL is a build dependency, not vendored source.

## 0.2.0 extensions

Zar adds zar_stream.h/.cpp: single-record streamed writer/reader, original
checksum compatibility, 64-bit file lengths and byte-range seeking. Catalogs
retain the original Store snapshot format around a versioned metadata payload.
HttpdWin's adapted transport streams request/response bodies, supports
100-continue and authenticates before accepting uploads. The original
interpreter backend remains absent. OpenSSL SSL is now also linked for the
outbound peer HTTPS client; certificate verification is mandatory.
