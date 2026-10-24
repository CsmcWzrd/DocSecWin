# Validation — 25 October 2026, release 0.2.0

Linux build: GCC 13.3.0, C++17, OpenSSL 3.0.13, GNU Make.
The optimized server build completed. Twelve integration scenarios passed:

1. Login failures/success, malformed credentials, bearer authorization, logout.
2. Hierarchy rules, UTF-8 titles, multi-block binary round trips, HEAD, update,
   listing, deletion conflicts and recursive deletion.
3. Independent Alice/alice/Bob folders and archives, hashes and POSIX permissions.
4. Invalid paths, traversal, malformed UTF-8 titles, unsupported queries/methods.
5. HTTP/1.1 framing, Host, duplicate headers, missing/invalid/overflowing lengths,
   incomplete bodies and unsupported transfer encoding.
6. Concurrent writes, exclusive process locking, persistence and session restart.
7. Corrupt catalog rejection without repair or rewrite.
8. Symlink rejection without modifying the link target.
9. ASCII/UTF-8/UTF-16 LE/BE/UTF-32 LE/BE, JSON/XML-like/BLOB byte preservation,
   document/section notes, POST-generated IDs, a 16 MiB+ upload/download, zero
   length, range/suffix/open ranges, verify, and interrupted-upload cleanup.
10. Reverse chronology, exact uint64 metadata, Zar filters, JSON _find,
    projection, snapshot pagination, ETags/If-Match, duplicate JSON rejection,
    unsupported selector rejection and authenticated 100-continue.
11. Two-server recursive pull, backend-only routing, local isolation, overwrite
    policy, source provenance, configured-peer/path restrictions, verified HTTPS,
    TLS hostname mismatch rejection, and remote hash mismatch before local commit.
12. Reading/migrating a real v1-format fixture without changing its UTF-16 bytes,
    and offline garbage collection preserving referenced data.

Native Zar tests passed: streamed archives are readable by the original binary
Store reader/checksum logic; partial reads cross block boundaries; an actual
sparse 5 GiB archive is range-read at an offset beyond 4 GiB without allocating
or physically uploading 5 GiB. The latter is a file-offset/range test, not a
claim that a multi-gigabyte network transfer was performed. The HTTP transfer
fixture is 16 MiB+. The sparse native fixture runs on the tested little-endian
Linux host and is excluded from Windows execution pending qualification.

The AddressSanitizer/UndefinedBehaviorSanitizer server build passed the same
12 integration scenarios. LeakSanitizer was disabled because this execution
environment uses tracing and does not support LeakSanitizer under ptrace.
The enabled checks reported no memory or undefined-behavior findings.

The OpenAPI JSON was parsed and its path/request schema references checked.
No interpreter backend, Python.h include, Python bindings or script dispatch
is present in the native server build. Optional Python code is a test client.

## Outstanding qualification / scope

CMake execution and native Windows/macOS builds were not available here.
Windows ACL/reparse-point handling, cross-architecture/endian execution,
long-duration load, large real-disk/network transfers, crash/power-loss fault
injection, and a full security review remain outstanding. Source includes
those OS paths; this is not a claim that they have been executed or passed.
Compiler warnings remain in the adapted and compact implementation sources;
the build is not represented as warning-free.

No native inbound TLS, IPv6 listener/peer origin, Windows service installation,
resumable/chunked upload, full-text/payload JSON indexing, history API, automatic
GC, online backup, encryption at rest, background pull scheduling, distributed
transaction or point-in-time subtree replication is implemented. Internal pulls
commit each item independently and report partial success explicitly.

The database serializes storage operations; an upload/scan can delay other
users. The catalog has documented metadata/resource bounds. Payload length
uses signed 64-bit local file offsets and is constrained by available storage
and the underlying filesystem. This release is functional and tested within
that scope, not fully production-qualified.
