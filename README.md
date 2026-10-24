# DocSecWin 0.2.0

Native C++17 HTTP/1.1 Document ↔ Section ↔ Information/Data server, with notes,
metadata queries, large-file streaming, and internal server-to-server pulls.
HttpdWin and Zar sources are included under third_party. The Python backend
is removed; the executable does not require Python. Optional integration
tests use Python as a client only.

## New in this release

- POST creation, PUT store/update, PATCH metadata, GET/HEAD retrieval and DELETE.
- Notes on documents and sections; CLOB/BLOB/JSON/XML-like data and raw files.
- Byte-preserving ASCII, UTF-8, UTF-16 LE/BE and UTF-32 LE/BE storage.
- Chronological/reverse queries, pagination, projection, and JSON _find selectors.
- Zar identity/timestamp/flags/extra/additional/counter/checksum selectors.
- Streaming upload/download with 64-bit lengths, byte ranges and integrity scans.
- Authenticated internal pull from named DocSecWin peers into the local database.
- Backend mode that hides public data routes and serves internal processing APIs.

[API reference](docs/API.md) · [Internal backend guide](docs/BACKEND.md) ·
[Storage and migration](docs/STORAGE.md) · [OpenAPI](docs/openapi.json) ·
[Validation](docs/VALIDATION.md)

## Build

Requires a **64-bit** C++17 toolchain and OpenSSL SSL/Crypto development
headers/libraries. OpenSSL provides authentication, hashing, random tokens,
and verified outbound HTTPS; Zar provides on-disk storage. No external
database or interpreter backend is used.

Windows 10/11, Visual Studio 2022 Developer PowerShell (Desktop development
with C++ workload, CMake and x64 OpenSSL installed):

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DOPENSSL_ROOT_DIR="C:/OpenSSL-Win64" -DBUILD_TESTING=OFF
cmake --build build --config Release
.\build\Release\DocSecWin.exe add-user C:\DocSecWinData Processor
.\build\Release\DocSecWin.exe backend C:\DocSecWinData 8081
```

CMake generates build/DocSecWin.sln and associated projects. Set a restrictive
NTFS ACL on the root for the server identity and administrators before
provisioning users. There is no automatic Windows service/ACL installation.
Deploy the matching OpenSSL runtime libraries when using a shared OpenSSL build.

Linux/macOS with compiler, GNU Make and OpenSSL development files installed:

```sh
make -j4
./DocSecWin add-user ./data Alice
./DocSecWin serve ./data 8080
```

On Debian/Ubuntu the build packages are build-essential and libssl-dev.
Alternatively run `cmake -S . -B build -DBUILD_TESTING=OFF` and
`cmake --build build`. For non-default OpenSSL prefixes, pass
`-DOPENSSL_ROOT_DIR=/path/to/openssl`. On macOS use Xcode command-line tools
and the appropriate OpenSSL prefix. No Python discovery is needed unless
BUILD_TESTING is enabled.

add-user reads a 12–1024-byte password from stdin (interactive input currently
echoes). The default listener is 127.0.0.1:8080; optionally specify a numeric
IPv4 bind address as the fifth argument. Stop with Ctrl+C.

## Modes and endpoints

`DocSecWin serve ROOT PORT` provides the normal document API. For an internal
backend, configure ROOT/peers.conf and run `DocSecWin backend ROOT PORT`.
Backend mode disables public /api/v1/documents routes. It exposes:

- POST /api/v1/internal/pull — persist copies from an authorized remote peer.
- GET /api/v1/internal/peers — configured destinations, without secrets.
- /api/v1/internal/local/documents/... — authenticated local processing APIs.

Both modes provide login/logout and liveness. Every login has its own folder,
account record, documents.zar metadata catalog and streamed Zar payload files.
Peer tokens are not persisted. Backend mode still requires authentication
and appropriate OS/network controls. Native inbound TLS is not included;
use a trusted reverse proxy for remote inbound access.

## Quick resource example

Login with `curl --http1.1 -u Alice -X POST -d '' http://127.0.0.1:8080/api/v1/login`
and set TOKEN to the returned bearer token:

```sh
curl --http1.1 -H "Authorization: Bearer $TOKEN" -X PUT --data-binary 'Manual' http://127.0.0.1:8080/api/v1/documents/manual
curl --http1.1 -H "Authorization: Bearer $TOKEN" -X PUT --data-binary 'Introduction' http://127.0.0.1:8080/api/v1/documents/manual/sections/intro
curl --http1.1 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/octet-stream' -X PUT --data-binary @large-file.bin http://127.0.0.1:8080/api/v1/documents/manual/sections/intro/data/file
curl --http1.1 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: text/plain; charset=utf-8' --data-binary 'Document note' http://127.0.0.1:8080/api/v1/documents/manual/notes
curl --http1.1 -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:8080/api/v1/documents/manual/sections/intro/data?sort=updated_at&order=desc&limit=10'
```

Use curl.exe and PowerShell variable syntax on Windows. Requests use
Content-Length; Expect: 100-continue is supported, chunked uploads are not.
File size is limited by storage and signed 64-bit offsets, not the former
8 MiB ingress or 64 MiB snapshot payload limit. Catalog metadata remains bounded.

## Tests and qualification

Run `make test`, or enable BUILD_TESTING with CMake and use ctest. Integration
tests additionally need Python 3 and the openssl CLI for HTTPS fixtures.
The Linux build, functional integration and native Zar streaming tests are
verified. Windows/macOS builds, OS-specific qualification, prolonged load and
crash/power-loss fault injection remain outstanding. See docs/VALIDATION.md
for exact evidence. This is an initial working release, not a claim of full
production database qualification.
