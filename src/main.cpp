#include "database.h"
#include "pull.h"
#include <iostream>
#ifndef _WIN32
#include <sys/stat.h>
#endif
int main(int argc,char** argv) {
    try {
#ifndef _WIN32
        umask(0077);
#endif
        if(argc<3) {
            std::cout<<"DocSecWin 0.2.0\nUsage:\n  DocSecWin add-user ROOT USERNAME   (password from stdin)\n  DocSecWin gc ROOT USERNAME        (offline payload garbage collection)\n  DocSecWin backend ROOT [PORT [BIND_IPV4]] (internal routes only)\n  DocSecWin serve ROOT [PORT [BIND_IPV4]]\nDefault: 127.0.0.1:8080; terminate with Ctrl+C.\n";return 2;
        }
        std::string command=argv[1];docsec::fs::path root=docsec::fs::absolute(argv[2]);
        docsec::RootLock lock(root);docsec::Security security(root);
        if(command=="add-user" && argc==4) {
            std::string password;std::cerr<<"Password (12+ bytes; input is not masked): ";
            if(!std::getline(std::cin,password)) throw std::runtime_error("cannot read password");
            security.addUser(argv[3],password);
            docsec::Database database(root);
            database.initialize(argv[3]);
            std::cout<<"User created.\n";return 0;
        }
        if(command=="gc" && argc==4){docsec::Database database(root);std::cout<<database.collectGarbage(argv[3])<<" unreferenced payload files removed.\n";return 0;}
        if((command!="serve" && command!="backend") || argc>5) throw std::runtime_error("invalid command; run without arguments for usage");
        unsigned long port=8080;
        if(argc>=4) {std::string value=argv[3];if(value.empty()||value.find_first_not_of("0123456789")!=std::string::npos) throw std::runtime_error("invalid port");port=std::stoul(value);}
        if(port<1||port>65535) throw std::runtime_error("port must be 1-65535");
        std::string bind=argc==5?argv[4]:"127.0.0.1";docsec::Database database(root);docsec::PullService pulls(database,root);bool backend=command=="backend";
        std::cout<<"DocSecWin HTTP/1.1 listening on "<<bind<<":"<<port<<std::endl;
        docsec::serve(bind,static_cast<unsigned short>(port),[&](const docsec::Request& r) {
            if(r.target=="/healthz" && (r.method=="GET"||r.method=="HEAD")) {
                docsec::Response response;response.body="{\"status\":\"ok\",\"server\":\"DocSecWin\"}";return response;
            }
            if(r.target=="/api/v1/login" && r.method=="POST") return security.login(r);
            auto user=security.authenticate(r);
            if(r.target=="/api/v1/logout" && r.method=="POST") return security.logout(r);
            if(r.target=="/api/v1/internal/peers" && r.method=="GET")return pulls.listPeers();
            if(r.target=="/api/v1/internal/pull"){if(r.method!="POST")throw docsec::HttpError(405,"pull requires POST","POST");return pulls.pull(user,r);}
            const std::string local="/api/v1/internal/local/documents";
            if(r.target==local || r.target.compare(0,local.size()+1,local+"/")==0 || r.target.compare(0,local.size()+1,local+"?")==0){auto mapped=r;mapped.target="/api/v1/documents"+r.target.substr(local.size());return database.handle(user,mapped);}
            if(backend)throw docsec::HttpError(404,"backend mode exposes authenticated internal routes only");
            return database.handle(user,r);
        });
    } catch(const std::exception& e) {std::cerr<<"DocSecWin: "<<e.what()<<'\n';return 1;}
}
