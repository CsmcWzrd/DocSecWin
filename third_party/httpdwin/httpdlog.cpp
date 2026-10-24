//Copyright Anoop Kumar Narayanan - 2025 //httpdwin
#define _CRT_SECURE_NO_WARNINGS
#include <httpdlog.h>
#include <mutex>
#include <chrono>
#ifdef MAC_TAHOE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif
using namespace std;

#define _CRT_SECURE_NO_WARNINGS

int httpdloglevel = 4;

mutex logmutex;

void httpdlog(const char *level, string info ){
    auto timenow = std::chrono::system_clock::now();
    auto duration = timenow.time_since_epoch(); // duration since epoch
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
    logmutex.lock();
    switch (level[0]) {
        case 'D':
            if (httpdloglevel >= 3)
                std::cerr << "DEBUG" << " : " << micros << " : " << info << endl;
            break;
        case 'I':
            if (httpdloglevel >= 2)
                std::cerr << "INFO" << "  : " << micros << " : " << info << endl;
            break;
        case 'W':
            if (httpdloglevel >= 1)
                std::cerr << "WARN" << "  : " << micros << " : " << info << endl;
            break;
        case 'E':
            if (httpdloglevel >= 0)
                std::cerr << "ERROR" << " : " << micros << " : " << info << endl;
            break;
        case 'X':
            if (httpdloglevel >= 4)
                std::cerr << "XTRA " << " : " << micros << " : " << info << endl;
            break;
        case ' ':
            if (httpdloglevel >= 0)
                std::cerr << "     " << " : " << micros << " : " << info << endl;
            break;
        default:
            if (httpdloglevel >= 4)
                std::cerr << "     " << " : " << micros << " : " << info << endl;
            break;
       }
    logmutex.unlock();
    std::cerr.flush();
}


void httpdlogHdr(const char* level, string info) {

    logmutex.lock();
    if (httpdloglevel >= 4)
        cerr << "Header " << " : \n"<< info << endl;
    logmutex.unlock();
    cerr.flush();
}

#ifdef MAC_TAHOE
thread_local char correctedDir[2048] = {0};
thread_local char homeDir[2048] = {0};
char * HttpdWinDir(const char *folder){
    if( homeDir[0] == 0 ){
	strcpy( homeDir, getenv("HOME"));
        strcpy( correctedDir, homeDir);
    } else {
        strcpy( correctedDir, homeDir);
    }
    strcat( correctedDir, &folder[1]);
    //printf(correctedDir);
    return correctedDir;
}
#endif


