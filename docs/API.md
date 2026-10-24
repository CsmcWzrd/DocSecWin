# DocSecWin HTTP/1.1 API — 0.2.0

All information belongs to the authenticated login. Send
`Authorization: Bearer TOKEN`; obtain a one-hour token using HTTP Basic on
`POST /api/v1/login` with an empty body. `POST /api/v1/logout` revokes it.
`GET /healthz` is unauthenticated liveness only.

## Resource URLs

Let D be `/api/v1/documents/{document}` and S be
`/api/v1/documents/{document}/sections/{section}`. IDs are client-selected,
case-sensitive 1–64 ASCII letters/digits, hyphen or underscore. `_find` is
reserved. Titles, notes, and data support the encodings described below.

| Collection | Item URL | Purpose |
| --- | --- | --- |
| `/api/v1/documents` | D | Documents |
| `D/sections` | S | Sections belonging to a document |
| `D/notes` | `D/notes/{note}` | Notes attached to a document |
| `S/notes` | `S/notes/{note}` | Notes attached to a section |
| `S/data` | `S/data/{item}` | Information, files, CLOBs, BLOBs, JSON, XML-like data |

| Method | URL | Behavior |
| --- | --- | --- |
| POST | Any collection | Add a new resource; 201 and Location |
| PUT | Any item | Store/upsert or replace content; 201 new, 200 existing |
| GET / HEAD | Any item | Retrieve content or document/section metadata |
| GET / HEAD | `item/metadata` | Full searchable metadata without the payload |
| PATCH | Any item or `item/metadata` | Update metadata; item must already exist |
| GET | `data-item/verify` or `note/verify` | Stream through stored content and verify Zar checksum plus SHA-256 |
| GET / HEAD | Any collection | List/select with filters, sorting, pagination, projection |
| POST | `collection/_find` | DocumentDB-style JSON selector and query options |
| DELETE | Any item | Delete; a nonempty parent requires `?recursive=true` |

Create parents first. Updating a document/section preserves its descendants.
Deletion removes the catalog references atomically; offline GC reclaims old
payload archives. Reverse chronological retrieval uses a sorted listing and
the returned content URL, for example `S/data?sort=timestamp&order=desc&limit=1`.

## Creating and storing

POST a document or section using JSON:

```json
{"id":"manual","title":"User manual","tags":["guide"],"attributes":{"team":"engineering"}}
```

Omit id to generate one. PUT also accepts this metadata JSON without id when
Content-Type is application/json. For compatibility, a raw UTF-8 title is
accepted by document/section PUT with any other Content-Type. Titles are at
most 4096 bytes. Metadata request bodies are bounded at 256 KiB.

POST/PUT data and notes with the **raw content bytes** and the appropriate
Content-Type. A JSON data body is the data itself, not a creation envelope.
POST generates an ID unless `X-DocSec-Id` supplies one. Notes default to CLOB
with `text/plain; charset=utf-8`; data defaults to BLOB/application/octet-stream.
Empty bodies are supported. The server preserves bytes, BOMs, line endings,
and byte order. It does not transcode, validate payload character encoding,
parse XML-like content, or impose a JSON document schema on stored content.

| Content | Suggested headers |
| --- | --- |
| CLOB | `Content-Type: text/plain; charset=utf-8`, `X-DocSec-Kind: clob` |
| BLOB / binary file | `Content-Type: application/octet-stream`, `X-DocSec-Kind: blob` |
| JSON | `Content-Type: application/json` |
| XML / XML-like | `Content-Type: application/xml` |
| ASCII | `Content-Type: text/plain; charset=us-ascii` |
| UTF-8 | `Content-Type: text/plain; charset=utf-8` |
| UTF-16 | `charset=utf-16`, `utf-16le`, or `utf-16be` |
| UTF-32 | `charset=utf-32`, `utf-32le`, or `utf-32be` |

`X-DocSec-Encoding` can explicitly declare binary/ascii/utf-8/utf-16/utf-16le/
utf-16be/utf-32/utf-32le/utf-32be. Kind values are clob/blob/json/xml/text/binary.
Kind and encoding labels are normalized to lowercase. Optional upload headers:
`X-DocSec-Title`, `X-DocSec-Flags`, `X-DocSec-Extra`, `X-DocSec-Additional`,
`X-DocSec-Timestamp`, and `X-DocSec-Counters` (JSON array of 14 uint64 values).
Use PATCH for tags and custom attributes.

## Metadata and Zar fields

A metadata representation includes:

- id, url, resource_type, title, kind, encoding, content_type, size, revision.
- archive_id (numeric resource identity, stable across updates).
- created_at and updated_at: server-generated Unix microseconds.
- timestamp: queryable Zar timestamp, Unix microseconds by default, optionally
  set by the caller. Sort by updated_at for ingestion order or timestamp for
  application/source chronology. Imported source dates also appear in provenance.
- flags (uint64), extra (uint32), additional (16 bytes as 32 lowercase hex chars),
  counters (14 uint64 values), sha256 (64 hex chars), zar_checksum (128 hex chars).
- tags (up to 64 strings), attributes (custom JSON object, at most 64 KiB, maximum nesting 16).

PATCH accepts title/content_type/kind/encoding/timestamp/flags/extra/additional/
counters/tags/attributes. Arrays and attributes are replaced as whole values.
Other fields are read-only. Revisions increment on PUT/PATCH. Recreating a
deleted ID starts a fresh resource. Content is replaced using PUT, not PATCH.

Example PATCH:

```json
{"title":"Results","flags":5,"extra":2,"tags":["approved"],"attributes":{"project":"DocSecWin","score":92}}
```

The catalog provides these logical Zar field selectors. It is authoritative
for current metadata; a metadata-only PATCH does not rewrite an immutable
payload's historical Zar header. sha256 and zar_checksum describe content.

## Lists, reverse chronology, and selective queries

GET collection parameters:

| Parameter | Meaning |
| --- | --- |
| sort, order | Metadata field and asc/desc; default id ascending |
| limit, offset / skip | Page size 1–1000 (default 100), offset |
| fields | Comma-separated top-level metadata names |
| recursive=true | Include descendants under the collection |
| snapshot | Token from the first page; reject changed catalogs with 409 |
| id, resource_type, kind, content_type, encoding | Exact string selectors |
| tag, title_prefix | Tag membership or title prefix |
| archive_id, flags, extra, timestamp | Exact uint64 selectors |
| flags_all | Require all specified flag bits |
| id_min/max or archive_id_min/max | Inclusive numeric archive identity range |
| timestamp_min/max, created_at_min/max, updated_at_min/max | Inclusive timestamp ranges |
| size_min/max, revision_min/max | Inclusive numeric ranges |
| sha256, checksum / zar_checksum, additional | Exact hexadecimal fields |
| counter0 through counter13 | Exact counter; append _min/_max for ranges |
| selector | URL-encoded JSON selector; prefer POST _find for complex queries |

Filters are ANDed. Listings include items, total_count, returned_count,
next_offset (or null), and snapshot. Preserve the same query and snapshot
across pages for change detection. Offset pagination is not a server-held
snapshot; a changed catalog requires restarting the listing.

Example _find request:

```json
{
  "selector": {
    "$and": [
      {"flags":{"$bitsAllSet":1}},
      {"attributes.project":"DocSecWin"},
      {"timestamp":{"$gte":1700000000000000}},
      {"tags":{"$contains":"approved"}}
    ]
  },
  "sort":[{"timestamp":"desc"},{"archive_id":"desc"}],
  "fields":["id","url","title","timestamp","size","sha256"],
  "limit":50,
  "skip":0
}
```

Supported operators: $eq, $ne, $gt, $gte, $lt, $lte, $in, $exists, $prefix,
$contains (substring or string membership), $bitsAllSet, $and, $or. Dotted
fields access attributes and counters (e.g. counters.0). Integer comparisons
retain all 64 bits. Sort supports one field string or up to three field/order
objects, with stable identity/URL tie breaks. Projection uses top-level fields.
These selectors query **metadata**, not arbitrary fields inside stored JSON,
XML, text or BLOB content. Full-text/content indexing is not implemented.

## Large files and conditional HTTP

Uploads require decimal Content-Length and stream with fixed-size buffers.
There is no application-defined 8 MiB or 64 MiB **payload** limit. The actual
bounds are available storage, OS/filesystem limits, and a maximum declared
payload length of 2^63−1−32768 bytes in a 64-bit executable. The metadata
catalog remains capped at 64 MiB and 10000 resources per login.

`Expect: 100-continue` is supported after authentication and upload validation.
There is a 30-second idle I/O timeout, not a 20-second whole-file deadline.
Transfers are not resumable; interrupted uploads do not replace an existing
item. Chunked request bodies remain unsupported.

GET/HEAD supports a single byte range: `Range: bytes=START-END`, `bytes=START-`,
or `bytes=-SUFFIX`. Success returns 206 and Content-Range. Invalid ranges return
416. If-Range accepts the current single ETag; a mismatch sends the full body.
Full downloads verify both stored Zar checksum and SHA-256 while streaming.
A detected late corruption closes the response before completion; clients
must reject truncated responses. Partial downloads do not verify untouched
bytes: use /verify for a complete integrity scan. X-Content-SHA256 describes
the complete payload, not the selected byte range.

GET metadata and content return ETag. PUT/PATCH/DELETE accept single If-Match
or *; a mismatch returns 412. If-None-Match: * on PUT prevents overwriting.
GET/HEAD with matching If-None-Match returns 304. Unconditional writes use
last-writer-wins. Authentication errors are 401; input 400; absent parent/item
404; unsupported method 405; nonempty deletion/stale page 409; missing length
411; metadata quota 413; media type 415; expectation 417; login rate 429;
headers 431; storage/integrity 500; framing 501; peer failure 502;
session capacity 503. Errors are JSON and hide internal exception details.

The native listener uses HTTP/1.1, Content-Length, one request per connection,
Connection: close, and Cache-Control: no-store. HTTPS inbound should terminate
at a trusted reverse proxy. [BACKEND.md](BACKEND.md) covers internal pull mode.
