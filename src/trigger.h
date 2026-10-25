#pragma once
#include "docsec_http.h"
#include <optional>
namespace docsec {
// Recognizes a bounded marker in a dedicated identifier or a User-Agent segment.
// The marker is consumed locally and is never forwarded to the remote server.
std::optional<std::string> clientRetrievalTarget(const Request& request);
}
