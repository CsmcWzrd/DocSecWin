//Copyright Anoop Kumar Narayanan - 2025 //httpdwin
#ifndef HTTPREQUEST_H_INCLUDED
#define HTTPREQUEST_H_INCLUDED

#include <iostream>
#include <fstream>
#include <map>

using namespace std;

#include "cookie.h"

const int MAXBUFFER = 1*1024*1024;
const std::time_t MAX_STALL = 20;

class NameMimeValues {
    public:
        string m_Name;
        string m_Mime;
        string m_Value;
        string m_TempFileName;
        fstream m_f;

        NameMimeValues & operator =( const NameMimeValues&);
};

typedef map<string, NameMimeValues*> Query;

class HttpRequest {
    private:
    public:

        string  m_ipAddress;
        string  m_port;
        string  m_Method;
        string  m_Version;
        string  m_DecodedUrl;
        string  m_EncodedUrl;
        string  m_RequestFile;
		string  m_ActualFile;
        Query   query;

        string  m_Filename;
        string  m_TempPostFileName;
        string  m_TempPutFileName;
        string  m_jsonFile;

        string  m_HeaderNames[164];
        string  m_Headers[164];
        int     m_FieldCount;
        bool    m_HttpHeaderComplete;

        CookieList* m_CookieList;

        unsigned char    m_Buffer[MAXBUFFER];
        size_t           m_Len;
        size_t           m_cLen;
		std::time_t      m_StartRequest;

		static string pagesFolder;

        HttpRequest();
        ~HttpRequest();

        enum HttpHeader {
        	Accept = 0,
        	Accept_CH,
        	Accept_Encoding,
        	Accept_Language,
        	Accept_Patch,
        	Accept_Post,
        	Accept_Ranges,
        	Access_Control_Allow_Credentials,
        	Access_Control_Allow_Headers,
        	Access_Control_Allow_Methods,
        	Access_Control_Allow_Origin,
        	Access_Control_Expose_Headers,
        	Access_Control_Max_Age,
        	Access_Control_Request_Headers,
        	Access_Control_Request_Method,
        	Age,
        	Allow,
        	Alt_Svc,
        	Alt_Used,
        	Attribution_Reporting_EligibleExperimental,
        	Attribution_Reporting_Register_SourceExperimental,
        	Attribution_Reporting_Register_TriggerExperimental,
        	Authorization,
        	Available_DictionaryExperimental,
        	Cache_Control,
        	Clear_Site_Data,
        	Connection,
        	Content_Digest,
        	Content_Disposition,
        	Content_DPRNon_standardDeprecated,
        	Content_Encoding,
        	Content_Language,
        	Content_Length,
        	Content_Location,
        	Content_Range,
        	Content_Security_Policy,
        	Content_Security_Policy_Report_Only,
        	Content_Type,
        	__Cookie,
        	Critical_CHExperimental,
        	Cross_Origin_Embedder_Policy,
        	Cross_Origin_Opener_Policy,
        	Cross_Origin_Resource_Policy,
        	Date,
        	Device_Memory,
        	Dictionary_IDExperimental,
        	DNTNon_standardDeprecated,
        	DownlinkExperimental,
        	DPRNon_standardDeprecated,
        	Early_DataExperimental,
        	ECTExperimental,
        	ETag,
        	Expect,
        	Expect_CTDeprecated,
        	Expires,
        	Forwarded,
        	From,
        	Host,
        	If_Match,
        	If_Modified_Since,
        	If_None_Match,
        	If_Range,
        	If_Unmodified_Since,
        	Keep_Alive,
        	Last_Modified,
        	Link,
        	Location,
        	Max_Forwards,
        	NELExperimental,
        	No_Vary_SearchExperimental,
        	Observe_Browsing_TopicsExperimentalNon_standard,
        	Origin,
        	Origin_Agent_Cluster,
        	Permissions_PolicyExperimental,
        	PragmaDeprecated,
        	Prefer,
        	Preference_Applied,
        	Priority,
        	Proxy_Authenticate,
        	Proxy_Authorization,
        	Range,
        	Referer,
        	Referrer_Policy,
        	Refresh,
        	Report_ToNon_standardDeprecated,
        	Reporting_Endpoints,
        	Repr_Digest,
        	Retry_After,
        	RTTExperimental,
        	Save_DataExperimental,
        	Sec_CH_Prefers_Color_SchemeExperimental,
        	Sec_CH_Prefers_Reduced_MotionExperimental,
        	Sec_CH_Prefers_Reduced_TransparencyExperimental,
        	Sec_CH_UAExperimental,
        	Sec_CH_UA_ArchExperimental,
        	Sec_CH_UA_BitnessExperimental,
        	Sec_CH_UA_Form_FactorsExperimental,
        	Sec_CH_UA_Full_VersionDeprecated,
        	Sec_CH_UA_Full_Version_ListExperimental,
        	Sec_CH_UA_MobileExperimental,
        	Sec_CH_UA_ModelExperimental,
        	Sec_CH_UA_PlatformExperimental,
        	Sec_CH_UA_Platform_VersionExperimental,
        	Sec_CH_UA_WoW64Experimental,
        	Sec_Fetch_Dest,
        	Sec_Fetch_Mode,
        	Sec_Fetch_Site,
        	Sec_Fetch_User,
        	Sec_GPCExperimental,
        	Sec_Purpose,
        	Sec_Speculation_TagsExperimental,
        	Sec_WebSocket_Accept,
        	Sec_WebSocket_Extensions,
        	Sec_WebSocket_Key,
        	Sec_WebSocket_Protocol,
        	Sec_WebSocket_Version,
        	Server,
        	Server_Timing,
        	Service_Worker,
        	Service_Worker_Allowed,
        	Service_Worker_Navigation_Preload,
        	Set_Cookie,
        	Set_Login,
        	SourceMap,
        	Speculation_RulesExperimental,
        	Strict_Transport_Security,
        	Supports_Loading_ModeExperimental,
        	TE,
        	Timing_Allow_Origin,
        	TkNon_standardDeprecated,
        	Trailer,
        	Transfer_Encoding,
        	Upgrade,
        	Upgrade_Insecure_Requests,
        	Use_As_DictionaryExperimental,
        	User_Agent,
        	Vary,
        	Via,
        	Viewport_WidthNon_standardDeprecated,
        	Want_Content_Digest,
        	Want_Repr_Digest,
        	WarningDeprecated,
        	WidthNon_standardDeprecated,
        	WWW_Authenticate,
        	X_Content_Type_Options,
        	X_DNS_Prefetch_ControlNon_standard,
        	X_Forwarded_ForNon_standard,
        	X_Forwarded_HostNon_standard,
        	X_Forwarded_ProtoNon_standard,
        	X_Frame_Options,
        	X_Permitted_Cross_Domain_PoliciesNon_standard,
        	X_Powered_ByNon_standard,
        	X_Robots_TagNon_standard,
        	X_XSS_ProtectionNon_standardDeprecated,
        };

        static CookieList* readCookies(HttpRequest* req, string& line, CookieList *);
        static void readHttpReqLine( HttpRequest *req, string &line );
		static void readHeaderLine ( HttpRequest *req, string &line );
		static void readHttpHeader ( HttpRequest *req, char *buffer, int *len, int totalLen);
		static void readHttpData   ( char *buffer, int *len, int totalLen, string *filename );

        void decodeUrl();
		string filenameCorrection(string filename );
        void parseQuerystring();
		
        void parsePostDataQueryString();
        void processPostData( string *filename );
        void processMultipartData ( string *filename );


};

#endif // HTTPREQUEST_H_INCLUDED

