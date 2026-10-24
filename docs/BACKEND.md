# Internal backend / server-to-server pull

DocSecWin can act as an HTTP/1.1 **client** of another DocSecWin server, then
store retrieved information in its own private Zar database for processing.
It uses a genuine authenticated GET client; it does not impersonate a login
without that login's credentials and does not proxy the remote response back
to the caller as the import result. Imported bytes are local persistent data.

## Configure and start

Create the local backend user:

```sh
./DocSecWin add-user ./backend-data Processor
```

Create `backend-data/peers.conf` as an administrator. One peer name and exact
origin per line, with no URL path or credentials:

```text
archive http://127.0.0.1:8080
production https://docsec-internal.example:8443
```

Restart to reload configuration. A request cannot supply a different origin.
Hostnames/IPv4 addresses are supported; IPv6 peer origins are not yet supported.
No redirects, environment HTTP proxies, arbitrary methods, cookie forwarding,
or caller-provided peer headers are used. Remote tokens are sent only to the
selected administrator-configured peer. HTTPS requires a valid trusted
certificate matching the configured hostname/IP; OpenSSL's default trust
paths and SSL_CERT_FILE can supply a private CA. Plain HTTP peers should be
confined to a trusted local/private connection.

```sh
./DocSecWin backend ./backend-data 8081
```

Backend mode exposes login/logout/health and authenticated `/api/v1/internal/*`
routes. The public `/api/v1/documents` data API returns 404 in this mode.
It binds to loopback by default. `serve` mode preserves the public data API
and also supports the authenticated internal routes.

## Endpoints

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/v1/internal/peers` | List configured peer names and origins; no secrets |
| POST | `/api/v1/internal/pull` | Fetch a resource/subtree and persist local copies |
| All documented resource methods | `/api/v1/internal/local/documents/...` | Authenticated processing access to the local database using the same APIs and selectors |

Login remotely to obtain a source_token and locally to obtain LOCAL_TOKEN.
These can belong to different usernames; the local bearer login owns the
resulting files and catalog. Existing local parents are required when pulling
only a section, note or data item. Pulling a whole document creates its root.

```sh
curl --http1.1 -u Processor -X POST -d '' http://127.0.0.1:8081/api/v1/login
curl --http1.1 -u SourceUser -X POST -d '' http://127.0.0.1:8080/api/v1/login
curl --http1.1 -H "Authorization: Bearer $LOCAL_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @pull.json http://127.0.0.1:8081/api/v1/internal/pull
```

Example pull.json (protect and remove this temporary file after use because
it contains a live token; applications should construct the JSON in memory):

```json
{
  "peer":"archive",
  "source_path":"/api/v1/documents/manual",
  "destination_path":"/api/v1/documents/local-manual",
  "source_token":"REMOTE_BEARER_TOKEN",
  "recursive":true,
  "overwrite":false
}
```

Source may instead use `/api/v1/internal/local/documents/...` when the remote
server itself runs in backend mode. Destination accepts either URL prefix;
its document/section/data/note shape must match the source shape. Omit it to
keep the source identifiers. Source paths cannot specify arbitrary websites,
files, query strings, or administrative endpoints.

A nonrecursive pull copies one document title, section title, data item or
note. A recursive document pull copies its sections, document notes, section
notes, and data. A recursive section pull copies that section and its notes
and data. It **does not delete** extra destination records. overwrite=false
uses create-only writes and fails with 412 on existing IDs; overwrite=true
updates local copies while retaining their local identity.

The response reports complete, imported_count and imported receipts containing
source URL, destination URL and local revision. GET a local copied item at:
`/api/v1/internal/local/documents/local-manual/sections/intro/data/example`.
Local listing and _find allow subsequent processing jobs to select those data.
No content transformation, model processing, or background scheduler is added
by the pull operation itself.

## Consistency, integrity and failure behavior

Pull is synchronous. Set the caller's response timeout long enough for the
transfer. The backend uses bounded-memory streaming for payloads, 30-second
peer connect/I/O waits (DNS uses the system resolver), and identity
Content-Length responses. A supported peer must run the expanded metadata API.
The full subtree is enumerated before writing its items. Listing pagination
uses peer snapshot change detection; metadata is refreshed before each item,
and its ETag is required on the payload GET. Payload length and SHA-256 must
match before that item is committed locally. The source and destination are
separate databases; this is not a cross-server transaction or point-in-time
subtree snapshot.

Each item commit is atomic; the entire recursive pull is not. If a later item
fails, previous items remain, and the error response includes imported_count,
receipts, and complete=false. There are no automatic retries. After inspecting
the receipt, retry with overwrite=true as appropriate. Remote failures map to
502; local conflicts/validation retain their status. The caller must inspect
both the HTTP status and complete flag.

Metadata (title/type/encoding/tags/attributes and Zar query fields) is copied.
Local revisions, archive identity and created/updated dates are generated
locally. attributes._docsec_source records peer name, path, source revision,
source SHA-256 and source dates. timestamp retains source application chronology.
Remote tokens are request-scoped and are not stored in catalogs, provenance,
configuration, receipts or logs. Per-user folder and authentication isolation
also apply to imported records. Protect the storage root and peers.conf with
OS permissions; the word internal is not a substitute for network controls.
