#ifndef __COOKIE_H__
#define __COOKIE_H__

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <map>
#include <string>
#include <mutex>
#include <list>
#include <httpdlog.h>
#include <random>
#include <cstdint>
#include <string.h>

using namespace std;

class Cookie {
	public:
	std::string m_gname;
	std::string m_name;
	std::string m_value;
	uint64_t m_maxage; // in seconds
    uint64_t m_time;
	std::string m_expires;
	bool   m_secure;
	bool   m_httpOnly;
	std::string m_sameSite; // Lax, Strict, None
	std::string m_path;
	std::string m_domain;

	Cookie();
	Cookie(const std::string& gname, const std::string& name, const std::string& value, std::string expires = "", uint64_t maxage = 0, bool secure = true, bool httpOnly = false, std::string path = "", std::string domain = "");
	void generateSessionId();
    void touchTime();

	bool operator==(const Cookie& other) const {
		return m_gname == other.m_gname;
	}

	static void convertToString(uint8_t* value, std::string& randomSessionId);
	static void generateRandomSessionId(std::string& randomSessionId);
	std::string toString();
	std::string toGroupString();
	void parseCookieStringWithGroup(const std::string& cookieStr);
	void parseCookieString(const std::string& cookieStr);
	void getCookieCStr(char* cookieCstr, size_t capacity);
};

typedef std::list<Cookie> CookieList;
typedef std::unordered_map<std::string, CookieList*> CookieMap;

class CookieManager {
	public:
	static   CookieMap m_cookies;
    uint64_t m_cookieGroupCleared;
	static std::mutex m_mutex;
	fstream m_file;

	CookieManager();
	~CookieManager();
	void openFile();
	void openFileForReading();
	void closeFile();
	void saveAll();
	//std::string load(CookieList* a_list);
	void loadAll();
	void add(Cookie* cookie);
	bool add(std::string gname, CookieList* cl);
	void print();
	void remove(Cookie* cookie);
	CookieList* get(string name);
	void get(string name, Cookie* cookie);
	void set(const Cookie& cookie);
	void clear(std::string name);
    void clearExpired();
};


#endif

