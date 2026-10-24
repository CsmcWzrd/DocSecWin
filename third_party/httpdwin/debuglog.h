#ifndef DEBUGLOG_H_INCLUDED
#define DEBUGLOG_H_INCLUDED

#include <iostream>
#include <string>
using namespace std;

void debuglog(char *level, string info ){
    switch(level[0]){
    case 'D':
        break;
    case 'I':
        break;
    case 'W':
        break;
    case 'E':
        break;
    case 'X':
        break;
    case ' ':
        break;
    default:
        break;
    }
}

#endif // DEBUGLOG_H_INCLUDED

