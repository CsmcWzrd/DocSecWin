//Copyright Anoop Kumar Narayanan - 2025 //httpdwin
#ifndef HTTPRESPONSE_H_INCLUDED
#define HTTPRESPONSE_H_INCLUDED

#include <fstream>
#include <iostream>
#include <map>

using namespace std;
#include <httprequest.h>

class HttpResponse:public HttpRequest{
    public:
        string m_ResponseHeader;

        string m_StatusCode;
        string m_StatusMessage;
        string m_ContentLength;
        string m_ContentType;
        string m_HttpData;

        size_t m_ResponseHeaderLen;

        fstream m_Fhandle;
        //string  m_ActualFile;
        string  m_Extension;
        size_t  m_ActualFileSize;

        bool    m_IsChunked;

        string  m_CollatedHeaders;

        std::time_t m_StartResponse;


        HttpResponse(string statusCode, string statusMessage, string contentLength, string contentType, string filename = "" );
        ~HttpResponse();

        void BuildResponseHeader(  std::map<string,string> *headers  );
        void addResponseData( string & data );
        size_t getFileSize();


        static map<string,string> mimeTypes;
        static map<string,string> textMimeTypes;

        static string filenameExtension ( string filename );

        
        static string getMime( string filename );
        static bool   isTextFile(string extension );

        static HttpResponse *CreateSimpleResponse( string filename );
        static HttpResponse *CreateSimpleResponse( string code, string smsg );
        static HttpResponse *CreateStringResponse( string str, string mime );
        static HttpResponse *CreateFileResponse  ( string filename );
};

#endif // HTTPRESPONSE_H_INCLUDED

