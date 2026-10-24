# HttpdWin adapted for DocSecWin

Upstream: https://github.com/CsmcWzrd/httpdwin
Commit: def06d5921da28d3c7156e2864ae9b7fd217c522

The original interpreter-driven entry point and worker implementation, script
bindings, sample website, and binary archives are omitted. Their replacement
is `docsec_http.h/.cpp`, a native bounded HTTP/1.1 transport with eight workers.
It calls the upstream `HttpResponse::BuildResponseHeader`; bodies are sent
separately for binary safety. Request/response/header/cookie/connection/logging
source is included. Legacy request parsing, file serving and cookie helpers
are not used by database routes. No interpreter backend is built or shipped.
Build only through the top-level DocSecWin build files.

Changes: explicit chrono include; capacity-aware cookie buffer helper;
legacy cookie-manager destructor no longer writes a global cookie file.
The executable supplies silent legacy log hooks. Sessions belong to the
DocSecWin security layer. Original source copyright notices are preserved.
The pinned repository has no standalone LICENSE file; no replacement license
is asserted for that upstream source.

0.2.0: request bodies are read lazily after authentication, with uint64 lengths
and 64 KiB buffers. Responses can stream Zar payloads. The adapter supports
100-continue, HEAD/error framing and binary-safe file transfers. The separate
peer client in src uses native HTTP/1.1 GET and verified OpenSSL TLS; it adds
no interpreter backend or subprocess dispatch.
