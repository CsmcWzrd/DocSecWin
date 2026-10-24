#pragma once
#include "database.h"
#include "peer_client.h"
namespace docsec {
class PullService {
    Database& database;
    std::map<std::string,Origin> peers;
public:
    PullService(Database& db,const fs::path& root);
    Response listPeers() const;
    Response pull(const std::string& user,const Request& request);
};
}
