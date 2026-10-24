//Copyright Anoop Kumar Narayanan - 2025 //httpdwin
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <exception>
#include <filesystem>
#include <chrono>
using namespace std;
using namespace std::filesystem;

#include <string.h>


#include <httpresponse.h>
#include <version.h>
#include <httpdlog.h>



extern thread_local int globalThreadId;

map<string,string> HttpResponse::mimeTypes =
{
{".aac"   ,"audio/aac" },
{".apng"  ,"image/apng" },
{".avi"   ,"video/x-msvideo" },
{".bin"   ,"application/octet-stream" },
{"."      ,"application/octet-stream" },
{".bmp"   ,"image/bmp" },
{".bz"    ,"application/x-bzip" },
{".bz2"   ,"application/x-bzip2" },
{".css"   ,"text/css" },
{".csv"   ,"text/csv" },
{".doc"   ,"application/msword" },
{".docx"  ,"application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
{".gz"    ,"application/x-gzip" },
{".gif"   ,"image/gif" },
{".htm"   ,"text/html" },
{".html"  ,"text/html" },
{".ico"   ,"image/vnd.microsoft.icon" },
{".jar"   ,"application/java-archive" },
{".jpeg"  ,"image/jpeg" },
{".jpg"   ,"image/jpeg" },
{".js"    ,"text/javascript" },
{".json"  ,"application/json" },
{".md"    ,"text/markdown" },
{".mp3"   ,"audio/mpeg" },
{".mp4"   ,"video/mp4" },
{".mpeg"  ,"video/mpeg" },
{".odp"   ,"application/vnd.oasis.opendocument.presentation" },
{".ods"   ,"application/vnd.oasis.opendocument.spreadsheet" },
{".odt"   ,"application/vnd.oasis.opendocument.text" },
{".oga"   ,"audio/ogg" },
{".ogv"   ,"video/ogg" },
{".ogx"   ,"application/ogg" },
{".opus"  ,"audio/ogg" },
{".otf"   ,"font/otf" },
{".png"   ,"image/png" },
{".pdf"   ,"application/pdf" },
{".php"   ,"application/x-httpd-php" },
{".ppt"   ,"application/vnd.ms-powerpoint" },
{".pptx"  ,"application/vnd.openxmlformats-officedocument.presentationml.presentation" },
{".rar"   ,"application/vnd.rar" },
{".rtf"   ,"application/rtf" },
{".sh"    ,"application/x-sh" },
{".svg"   ,"image/svg+xml" },
{".tar"   ,"application/x-tar" },
{".tif"   ,"image/tiff" },
{".tiff"  ,"image/tiff" },
{".ttf"   ,"font/ttf" },
{".txt"   ,"text/plain" },
{".wav"   ,"audio/wav" },
{".weba"  ,"audio/webm" },
{".webm"  ,"video/webm" },
{".webp"  ,"image/webp" },
{".xhtml" ,"application/xhtml+xml" },
{".xls"   ,"application/vnd.ms-excel" },
{".xlsx"  ,"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
{".xml"   ,"text/xml" },
{".zip"   ,"application/zip" },
{".7z"    ,"application/x-7z-compressed" }
};


map<string,string> HttpResponse::textMimeTypes =
{
{".css"   ,"text/css" },
{".htm"   ,"text/html" },
{".html"  ,"text/html" },
{".js"    ,"text/javascript" },
{".json"  ,"application/json" },
{".md"    ,"text/markdown" },
{".php"   ,"application/x-httpd-php" },
{".sh"    ,"application/x-sh" },
{".svg"   ,"image/svg+xml" },
{".txt"   ,"text/plain" },
{".xhtml" ,"application/xhtml+xml" },
{".xml"   ,"text/xml" },
};




HttpResponse::HttpResponse(string statusCode, string statusMessage, string contentLength, string contentType, string filename ){
    m_Version = "HTTP/1.1";
    m_StatusCode = statusCode;
    m_StatusMessage = statusMessage;
    m_ContentType = contentType;
    m_ContentLength = contentLength;
    m_Filename   = filename;
    m_ActualFile = "";
    m_Extension  = "";
    m_ResponseHeader = "";
    m_ResponseHeaderLen = 0;
    m_ActualFileSize = 0;
    m_IsChunked = false;
    m_HttpData = m_Version + " " + statusCode + " " + statusMessage + " " + filename;
    const auto now = std::chrono::system_clock::now();
    const std::time_t nowsecs = std::chrono::system_clock::to_time_t(now);
    m_StartResponse = nowsecs;
    httpdlog("DEBUG", std::to_string(globalThreadId)+ ": Creating response object: " + to_string((unsigned long long int) this));
}

HttpResponse::~HttpResponse() {
    if (m_Fhandle.is_open())
        m_Fhandle.close();
    if (m_CookieList){
        m_CookieList->clear();
        m_CookieList = 0;
    }
    m_StartResponse = 0;
    httpdlog("DEBUG", std::to_string(globalThreadId) + ": Deleting response object: " + to_string((unsigned long long int) this));
}



string HttpResponse::filenameExtension(string filename){
    size_t pos = filename.find_last_of('.');
    if (pos != std::string::npos) {
        return filename.substr(pos + 1);
    }
    if( filename == "/" || filename == "")
        return "html";
    else
        return "";
}

string HttpResponse::getMime(string extension){
    string mime = "";
    try{
        mime = mimeTypes[ "." + extension];
    }catch ( exception e ){
        mime = "text/plain";
    }
    return mime;
}

bool HttpResponse::isTextFile( string extension ){
    string mime = "";
    try{
        mime = textMimeTypes[ "." + extension];
    }catch ( exception e ){
        mime = "";
    }
    if( mime == "" )
        return false;
    else
        return true;
}

HttpResponse *HttpResponse::CreateSimpleResponse( string filename  ){
    httpdlog("XTRA:", std::to_string(globalThreadId) + ": Creating simple response ");
    HttpResponse *resp = new HttpResponse("200", "OK", "", "text/plain", filename );
    resp->m_ContentLength = std::to_string( (resp->m_HttpData).length() );
    return resp;
}

HttpResponse *HttpResponse::CreateSimpleResponse( string code, string smsg ){
    httpdlog("XTRA:", std::to_string(globalThreadId) + ": Creating simple response status code ");
    HttpResponse *resp = new HttpResponse(code, smsg , "", "text/plain", "" );
    resp->m_ContentLength = std::to_string( (resp->m_HttpData).length() );
    return resp;
}

HttpResponse *HttpResponse::CreateStringResponse( string str, string mime ){
    httpdlog("XTRA:", std::to_string(globalThreadId) + ": Creating simple response string ");
    HttpResponse *resp = new HttpResponse("200", "OK", "", mime, "" );
    resp->m_HttpData = str;
    resp->m_ContentLength = std::to_string( (resp->m_HttpData).length() );
    return resp;
}

HttpResponse *HttpResponse::CreateFileResponse( string filename ){
    httpdlog("XTRA:", std::to_string(globalThreadId) + ": Creating simple response file ");
    HttpResponse *resp = new HttpResponse("200", "OK", "", "text/plain" , filename );
    resp->m_ActualFile = resp->filenameCorrection(filename );
#ifdef MAC_TAHOE
    resp->m_ActualFile = HWD( resp->m_ActualFile.c_str());
#endif
    httpdlog("DEBUG:", std::to_string(globalThreadId) + ": Retrieving file : "+ filename );

    string extension   = filenameExtension (filename );
    resp->m_Extension  = extension;
    string mime = getMime( extension );
    resp->m_ContentType = mime;

    //Change to XTRA
    httpdlog("INFO:", std::to_string(globalThreadId) + ": Accessing file : "+ resp->m_ActualFile+", "+extension+", "+resp->m_ContentType );

    try{
        resp->m_ActualFileSize = std::filesystem::file_size( resp->m_ActualFile );
        httpdlog("INFO:", std::to_string(globalThreadId) + ": Size of accessed file : "+ std::to_string( resp->m_ActualFileSize ) );
    } catch(exception e ){
        resp->m_ActualFileSize = 0;
    }

    bool isText = isTextFile("." + extension );
    if( isText ){
        httpdlog("INFO", std::to_string(globalThreadId) + ": Text file is being read ");
        resp->m_Fhandle.open( resp->m_ActualFile, ios::in|ios::binary );
    } else {
        httpdlog("INFO", std::to_string(globalThreadId) + ": Binary file is being read ");
        resp->m_Fhandle.open( resp->m_ActualFile, ios::in|ios::binary );
    }

    if( resp->m_Fhandle.is_open() ){
        return resp;
    } else {
        //delete resp;
        //return CreateSimpleResponse("404", "File not found");
		resp->m_StatusCode = "404"; 
		resp->m_StatusMessage = "File not found";
        return resp;
    }
}

void HttpResponse::BuildResponseHeader( std::map<string,string> *headers ){
    size_t n = 0;

    strcpy((char*)m_Buffer, m_Version.c_str());
    n = m_Version.length();

    strcat((char*)&m_Buffer[n], " ");
    n++;
    strcpy((char*)&m_Buffer[n], m_StatusCode.c_str());
    n+= m_StatusCode.length();

    strcat((char*)&m_Buffer[n], " ");
    n++;
    strcpy((char*)&m_Buffer[n], m_StatusMessage.c_str());
    n+= m_StatusMessage.length();

	extern int httpdloglevel;
    if (httpdloglevel < 3)
		httpdlog("WARN", std::to_string(globalThreadId) + ": Response header: " + m_Version + " " + m_StatusCode + " " + m_StatusMessage);
    else
	    httpdlog("DEBUG", std::to_string(globalThreadId) + ": Response header: " + m_Version + " " + m_StatusCode + " " + m_StatusMessage + " <- " +m_DecodedUrl);

    strcat((char*)&m_Buffer[n], "\r\n");
    n += 2;

    const char *server = "Server: " HTTPDWIN_NAME "-" HTTPDWIN_VERSION;

    strcpy((char*)&m_Buffer[n], server);
    n += strlen(server);
    strcat((char*)&m_Buffer[n], "\r\n");
    n += 2;

    if( m_IsChunked ){
        const string te ="Transfer-Encoding: chunked\r\n";
        strcpy((char*)&m_Buffer[n], te.c_str());
        n += te.length();
        //m_Buffer[0] = 0;
    } else {
        strcpy((char*)&m_Buffer[n], "Content-Length: ");
        n += strlen( "Content-Length: " );
        if (m_ActualFileSize == 0)
            m_ContentLength = std::to_string(m_HttpData.length());
        else
            m_ContentLength = std::to_string(m_ActualFileSize);
        strcpy((char*)&m_Buffer[n], m_ContentLength.c_str());
        n += m_ContentLength.length();
        strcat((char*)&m_Buffer[n], "\r\n");
        n += 2;
    }

    strcpy((char*)&m_Buffer[n], "Content-Type: ");
    n += strlen( "Content-Type: " );
    strcpy((char*)&m_Buffer[n], m_ContentType.c_str());
    n += m_ContentType.length();
    strcat((char*)&m_Buffer[n], "\r\n");
    n += 2;

    if( headers ){
        map<string,string>::iterator i = headers->begin();
        while( i != headers->end() ){
            strcpy((char*)&m_Buffer[n], i->first.c_str() );
            n += i->first.length();
            strcpy((char*)&m_Buffer[n], i->second.c_str());
            n += i->second.length();
            strcat((char*)&m_Buffer[n], "\r\n");
            n += 2;
            i++;
        }
    }

    if (m_CookieList) {
		CookieList::iterator i = m_CookieList->begin();
        while (i != m_CookieList->end()) {
            string cookieHeader = "Set-Cookie: " + i->toString() + "\r\n";
            strcpy((char*)&m_Buffer[n], cookieHeader.c_str());
            n += cookieHeader.length();
            ++i;
        }
    }

    if (m_CollatedHeaders.size() > 0) {
        strcpy((char*)&m_Buffer[n], m_CollatedHeaders.c_str());
        n += m_CollatedHeaders.length();
    }

    strcat((char*)&m_Buffer[n], "\r\n");
    n += 2;
    m_ResponseHeaderLen = n;

}

void HttpResponse::addResponseData( string & data ){
    strcpy( (char*)(&m_Buffer[m_ResponseHeaderLen]), data.c_str() );
}

size_t HttpResponse::getFileSize(){
    return m_ActualFileSize;
}

