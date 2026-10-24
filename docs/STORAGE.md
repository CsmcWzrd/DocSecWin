# Storage format v2 and large payloads

Each login has its own `ROOT/users/<SHA-256(case-sensitive username)>/`:

- account: username, random salt and password hash (same account format as v1).
- documents.zar: integrity-checked searchable catalog of that user's resources.
- payloads/<random-128-bit-id>.zar: immutable streamed file/note content.

Every persistent payload is a Zar archive, not a raw loose data file. Catalogs
and payloads are private to the login selected by its bearer session. Names
and HTTP IDs never become OS paths. Case-distinct logins remain separate on
Windows. Temporary uploads are created in the same private payload directory.

## Catalog

A catalog is one normal little-endian Zar record titled DocSecWin-catalog-v2.
Its data is 64 ASCII hex SHA-256 characters followed by UTF-8 JSON:
`{"schema":"DocSecWin/2","entities":{"key":{"meta":{...},"blob":"random-id"}}}`.
Keys retain the v1 hierarchy; notes additionally use document/notes/id and
document/sections/section/notes/id. Document/section titles live in metadata;
data/note entries reference a streamed payload archive. Zar's record checksum
and the payload SHA-256 protect the catalog. It is bounded to 64 MiB/10000
resources and validated on every operation. Queries scan metadata, not file
contents. File sizes do not count against the metadata catalog limit.

## Streamed Zar payloads

A payload archive has an 8192-byte index block whose only entry is 8192, then
one 256-byte Zar header, the resource key as title, raw file bytes, and padding
to 8192-byte alignment. Continuation blocks contain contiguous content bytes.
Headers and indices use little endian, with host conversion in the library.
64-bit header dataLength/file offsets support payloads beyond 4 GiB.
writeStream/StreamReader in third_party/Zar use fixed 64 KiB buffers. They retain
the upstream Zar checksum algorithm; SHA-256 supplies a stronger content digest.
The original Zar Store APIs remain bundled and can read normal-sized streamed
archives. Applications must use StreamReader for huge files rather than the
older all-in-memory read APIs.

A payload's initial Zar header records its numeric identity, timestamp, flags,
extra, additional bytes and counters. Later metadata-only PATCH operations
update the catalog, preserving immutable content. Current filtering therefore
uses catalog fields rather than stale payload-header metadata. Raw content
checksums remain unchanged by such metadata edits.

## Commit, retention and GC

A mutation writes and flushes a new random temporary payload first, then
atomically installs that immutable archive. It then writes and flushes a new
catalog and atomically replaces documents.zar. The catalog is the visibility
commit point. Failed/interrupted uploads do not publish a new resource or
replace an existing one. A force-terminated process can leave an unreferenced
complete payload or temporary file, never a half-published catalog entry.

Old/replaced/deleted payload archives are retained so an already-open download
can finish, including on Windows. Reclaim them while the server is stopped:

```sh
./DocSecWin gc ROOT USERNAME
```

GC removes only unreferenced payload archives and upload temporary files for
that login. It holds the exclusive root lock and cannot run beside a server.
Catalog .tmp files at the user folder level are uncommitted leftovers and can
be removed manually while stopped. Back up the **whole stopped per-user folder**
(or whole stopped root), not just documents.zar: referenced payloads are required.
There is no online backup, WAL, automatic GC, replication daemon or encryption
at rest. Server-to-server pulls are explicit import operations, not consensus.

Storage operations serialize under one database mutex; a large upload or
verify scan can delay other database operations. Eight HTTP workers and 64
queued connections remain. Metadata snapshots are rewritten on updates,
whereas large payloads are streamed separately. Local disk, signed 64-bit file
offsets and the OS/filesystem determine maximum payload size. Cross-host
filesystem locking and power-loss behavior are not qualified.

## v1 compatibility

The earlier DocSecWin-snapshot-v1 binary catalog is still readable. Existing
raw bytes and resource URLs are preserved. The first successful mutation
migrates its catalog and inline data to v2; migration does not run on a read.
Legacy revisions remain; creation/update dates unavailable in v1 are reported
as zero until a later update supplies an updated_at date. v1 did not supply
all new metadata, so defaults fill the additional query fields. Keep a backup
before upgrading; v2 writes cannot be opened by the old 0.1 server.

## Accounts and local controls

Account hashes remain PBKDF2-HMAC-SHA256, 600000 iterations, 32-byte output.
The ASCII representation of a 16-byte random salt is the 32-byte salt input.
Sessions remain random 256-bit bearer tokens, hashed only in memory, valid for
one hour; restart invalidates them. Login is globally capped at 60 attempts
per minute/process, with at most 4096 active sessions.

POSIX directories use 0700 and newly created files use umask 0077. Windows
requires administrator-provisioned root NTFS ACLs. Symlinks are rejected.
Windows reparse-point/junction qualification remains outstanding. Protect
peers.conf as an administrator-controlled outbound allowlist. Inbound HTTP
is plain HTTP/1.1; use a trusted TLS proxy for remote clients. Outbound peer
HTTPS verifies certificates and hostname/IP identity through OpenSSL.
