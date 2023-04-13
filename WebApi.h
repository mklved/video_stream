/*
 * Copyright (c) 2016 The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/xia-chu/ZLMediaKit).
 *
 * Use of this source code is governed by MIT license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#ifndef ZLMEDIAKIT_WEBAPI_H
#define ZLMEDIAKIT_WEBAPI_H

#include <string>
#include <iomanip>
#include <functional>
#include <algorithm>
#include <time.h>
#include "json/json.h"
#include "Common/Parser.h"
#include "Network/Socket.h"
#include "Http/HttpSession.h"
#include "Util/MD5.h"
#include "Common/MultiMediaSourceMuxer.h"
#ifdef ENABLE_MYSQL
#include "Util/SqlPool.h"
#endif // ENABLE_MYSQL




//配置文件路径
extern std::string g_ini_file;

namespace mediakit {
////////////RTSP服务器配置///////////
namespace Rtsp {
extern const std::string kPort;
} //namespace Rtsp

////////////RTMP服务器配置///////////
namespace Rtmp {
extern const std::string kPort;
} //namespace RTMP
}  // namespace mediakit

namespace API {
typedef enum {
    NotFound = -500,//未找到
    Exception = -400,//代码抛异常
    InvalidArgs = -300,//参数不合法
    SqlFailed = -200,//sql执行失败
    AuthFailed = -100,//鉴权失败
    OtherFailed = -1,//业务代码执行失败，
    Success = 0//执行成功
} ApiErr;
}//namespace API

class ApiRetException: public std::runtime_error {
public:
    ApiRetException(const char *str = "success" ,int code = API::Success):runtime_error(str){
        _code = code;
    }
    ~ApiRetException() = default;
    int code(){ return _code; }
private:
    int _code;
};

class AuthException : public ApiRetException {
public:
    AuthException(const char *str):ApiRetException(str,API::AuthFailed){}
    ~AuthException() = default;
};

class InvalidArgsException: public ApiRetException {
public:
    InvalidArgsException(const char *str):ApiRetException(str,API::InvalidArgs){}
    ~InvalidArgsException() = default;
};

class SuccessException: public ApiRetException {
public:
    SuccessException():ApiRetException("success",API::Success){}
    ~SuccessException() = default;
};

using ApiArgsType = std::map<std::string, std::string, mediakit::StrCaseCompare>;

template<typename Args, typename First>
std::string getValue(Args &args, const First &first) {
    return args[first];
}

template<typename First>
std::string getValue(Json::Value &args, const First &first) {
    return args[first].asString();
}

template<typename First>
std::string getValue(std::string &args, const First &first) {
    return "";
}

template<typename First>
std::string getValue(const mediakit::Parser &parser, const First &first) {
    auto ret = parser.getUrlArgs()[first];
    if (!ret.empty()) {
        return ret;
    }
    return parser.getHeader()[first];
}

template<typename First>
std::string getValue(mediakit::Parser &parser, const First &first) {
    return getValue((const mediakit::Parser &) parser, first);
}

template<typename Args, typename First>
std::string getValue(const mediakit::Parser &parser, Args &args, const First &first) {
    auto ret = getValue(args, first);
    if (!ret.empty()) {
        return ret;
    }
    return getValue(parser, first);
}

template<typename Args>
class HttpAllArgs {
public:
    HttpAllArgs(const mediakit::Parser &parser, Args &args) {
        _get_args = [&args]() {
            return (void *) &args;
        };
        _get_parser = [&parser]() -> const mediakit::Parser & {
            return parser;
        };
        _get_value = [](HttpAllArgs &that, const std::string &key) {
            return getValue(that.getParser(), that.getArgs(), key);
        };
        _clone = [&](HttpAllArgs &that) {
            that._get_args = [args]() {
                return (void *) &args;
            };
            that._get_parser = [parser]() -> const mediakit::Parser & {
                return parser;
            };
            that._get_value = [](HttpAllArgs &that, const std::string &key) {
                return getValue(that.getParser(), that.getArgs(), key);
            };
            that._cache_able = true;
        };
    }

    HttpAllArgs(const HttpAllArgs &that) {
        if (that._cache_able) {
            _get_args = that._get_args;
            _get_parser = that._get_parser;
            _get_value = that._get_value;
            _cache_able = true;
        } else {
            that._clone(*this);
        }
    }

    ~HttpAllArgs() = default;

    template<typename Key>
    toolkit::variant operator[](const Key &key) const {
        return (toolkit::variant)_get_value(*(HttpAllArgs*)this, key);
    }

    const mediakit::Parser &getParser() const {
        return _get_parser();
    }

    Args &getArgs() {
        return *((Args *) _get_args());
    }

    const Args &getArgs() const {
        return *((Args *) _get_args());
    }

private:
    bool _cache_able = false;
    std::function<void *() > _get_args;
    std::function<const mediakit::Parser &() > _get_parser;
    std::function<std::string(HttpAllArgs &that, const std::string &key)> _get_value;
    std::function<void(HttpAllArgs &that) > _clone;
};


namespace usrinfo {

class Usrpri {
public:
    Usrpri(const std::string &name, const std::string &key) {
        usrname = name;
        pushkey = key;
        checkpushkey();
        createToken();
        getStation();
    }
    Usrpri() = default;

    Json::Value getTokenInfo() {
        Json::Value tmp;
        tmp["usrname"] = usrname;
        tmp["pushkey"] = pushkey;
        tmp["token"] = token;
        char buffer1[80];
        strftime(buffer1, 80, "%Y-%m-%d %H:%M:%S", localtime(&create_time));
        tmp["create_time"] = buffer1;
        char buffer2[80];
        strftime(buffer2, 80, "%Y-%m-%d %H:%M:%S", localtime(&expiration_time));
        tmp["expiration_time"] = buffer2;
        return tmp;
    }

    Json::Value getTimeInfo() {
        Json::Value tmp;
        tmp["usrname"] = usrname;
        char buffer1[80];
        strftime(buffer1, 80, "%Y-%m-%d %H:%M:%S", localtime(&create_time));
        tmp["create_time"] = buffer1;
        char buffer2[80];
        strftime(buffer2, 80, "%Y-%m-%d %H:%M:%S", localtime(&expiration_time));
        tmp["expiration_time"] = buffer2;
        return tmp;
    }

    bool checkStation(const std::string &in_staiton, std::unordered_map<std::string, std::string> &map) {

        auto get_station = stringSplit(in_staiton, ',');

        std::vector<std::string> v;
        
        for (auto it : get_station) {
            v.push_back(map[it]);
        }
        std::sort(v.begin(), v.end());
        return isSubset(station, v);
    }
    std::string getToken() { return token; }
    std::string getname() { return usrname; }

    bool checkTokenTime() { 
        std::time_t now_time;
        time(&now_time);
        if (expiration_time > now_time) {
            expiration_time = now_time + 604800; // 604800 7天。
            return false;
        }
        else {
            return true;
        }
    }


    ~Usrpri() {}

private:
    void checkpushkey() {
        std::vector<std::map<std::string, std::string>> ret;
        const char *s = "SELECT pushKey FROM `user` WHERE username = '?'";
        toolkit::SqlWriter a(s);
        a << usrname;
        a << ret;
        if (ret.empty()) {
            throw AuthException("Unknow username");
        }
        if (pushkey != ret[0]["pushKey"]) {
            throw AuthException("pushkey error");
        }
    }

    void createToken() {
        time(&create_time);
        expiration_time = create_time + 604800; //604800 7天。
        std::string s = usrname + pushkey + asctime(localtime(&create_time));
        token = toolkit::MD5(s).hexdigest();
    }



    std::vector<std::string> stringSplit(const std::string &str, char delim) {
        std::size_t previous = 0;
        std::size_t current = str.find(delim);
        std::vector<std::string> elems;
        while (current != std::string::npos) {
            if (current > previous) {
                elems.push_back(str.substr(previous, current - previous));
            }
            previous = current + 1;
            current = str.find(delim, previous);
        }
        if (previous != str.size()) {
            elems.push_back(str.substr(previous));
        }
        // std::sort(elems.begin(), elems.end());
        return elems;
    }

    void getStation() {
        std::vector<std::map<std::string, std::string>> usr_ret;
        const char *usr_s = "select station from `user_station_mapping` where username = '?'";
        toolkit::SqlWriter user_station_mapping(usr_s);
        user_station_mapping << usrname;
        user_station_mapping << usr_ret;
        if (usr_ret.empty()) {
            throw AuthException("This user has no corresponding site ");
        }
        station = stringSplit(usr_ret[0]["station"], ',');
    }

    bool isSubset(std::vector<std::string> &v1, std::vector<std::string> &v2) {
        int i = 0, j = 0;
        while (i < v1.size() && j < v2.size()) {
            if (std::stoi(v1[i]) < std::stoi(v2[j])) {
                i++;
            } else if (v1[i] == v2[j]) {
                i++;
                j++;
            } else {
                return 0;
            }
        }
        if (j < v2.size())
            return 0;
        return 1;
    }

    

private:
    std::string usrname;
    std::string pushkey;
    std::string token;
    std::time_t create_time;
    std::time_t expiration_time;
    std::vector<std::string> station;
};

class UsrToken : public std::enable_shared_from_this<UsrToken> {
public:
    using Ptr = std::shared_ptr<UsrToken>;
    static UsrToken &Instance();
    ~UsrToken() {}

    Usrpri addToken(const std::string &name, const std::string &key) {
        Usrpri pri(name, key);

        if (checkmap(name)) {
            table.erase(table_map[name]);
        }
        table[pri.getToken()] = pri;
        table_map[name] = pri.getToken();
        return pri;
    }

    bool checkmap(const std::string &token) { return table_map.find(token) != table_map.end(); }

    bool checkToken(const std::string &token) { 
        auto it = table.find(token);

        if (it == table.end())
            return false;
        
        return true;
    }

    bool checkTokenTime(const std::string &token)
    {
        auto it = table.find(token);
        if (it->second.checkTokenTime()) {
            table_map.erase(it->second.getname());
            table.erase(it);
            return false;
        }
        return true;
    }

    bool checkStation(const std::string &token, const std::string &station) {
        Usrpri pri = table[token];
        return pri.checkStation(station, station_map);
    }

    Usrpri getpri(const std::string &token) {
        return  table[token];
    }

    std::string getstation(const std::string &station) 
    { 
        return station_map[station];
    }


private:
    UsrToken() { updateStationMap(); }

    void updateStationMap() { //未实现自动更新station_map.
        // station id map
        std::vector<std::map<std::string, std::string>> station_ret;
        const char *sta_s = "select station_id, station_name from `station_mapping` ";
        toolkit::SqlWriter station_mapping(sta_s);
        station_mapping << station_ret;
        if (station_ret.empty()) {
            throw AuthException("Unknow Error");
        }
        for (auto it : station_ret) {
            station_map[it["station_name"]] = it["station_id"];
        }
    }

private:
    std::unordered_map<std::string, Usrpri> table;
    std::unordered_map<std::string, std::string> table_map;
    std::unordered_map<std::string, std::string> station_map;
};

}





#define API_ARGS_MAP toolkit::SockInfo &sender, mediakit::HttpSession::KeyValue &headerOut, const HttpAllArgs<ApiArgsType> &allArgs, Json::Value &val
#define API_ARGS_MAP_ASYNC API_ARGS_MAP, const mediakit::HttpSession::HttpResponseInvoker &invoker
#define API_ARGS_JSON toolkit::SockInfo &sender, mediakit::HttpSession::KeyValue &headerOut, const HttpAllArgs<Json::Value> &allArgs, Json::Value &val
#define API_ARGS_JSON_ASYNC API_ARGS_JSON, const mediakit::HttpSession::HttpResponseInvoker &invoker
#define API_ARGS_STRING toolkit::SockInfo &sender, mediakit::HttpSession::KeyValue &headerOut, const HttpAllArgs<std::string> &allArgs, Json::Value &val
#define API_ARGS_STRING_ASYNC API_ARGS_STRING, const mediakit::HttpSession::HttpResponseInvoker &invoker
#define API_ARGS_VALUE sender, headerOut, allArgs, val

//注册http请求参数是map<string, variant, StrCaseCompare>类型的http api
void api_regist(const std::string &api_path, const std::function<void(API_ARGS_MAP)> &func);
//注册http请求参数是map<string, variant, StrCaseCompare>类型,但是可以异步回复的的http api
void api_regist(const std::string &api_path, const std::function<void(API_ARGS_MAP_ASYNC)> &func);

//注册http请求参数是Json::Value类型的http api(可以支持多级嵌套的json参数对象)
void api_regist(const std::string &api_path, const std::function<void(API_ARGS_JSON)> &func);
//注册http请求参数是Json::Value类型，但是可以异步回复的的http api
void api_regist(const std::string &api_path, const std::function<void(API_ARGS_JSON_ASYNC)> &func);

//注册http请求参数是http原始请求信息的http api
void api_regist(const std::string &api_path, const std::function<void(API_ARGS_STRING)> &func);
//注册http请求参数是http原始请求信息的异步回复的http api
void api_regist(const std::string &api_path, const std::function<void(API_ARGS_STRING_ASYNC)> &func);



//注册http请求参数是map<string, variant, StrCaseCompare>类型的http api
void usr_api_regist(const std::string &api_path, const std::function<void(API_ARGS_MAP)> &func);
//注册http请求参数是map<string, variant, StrCaseCompare>类型,但是可以异步回复的的http api
void usr_api_regist(const std::string &api_path, const std::function<void(API_ARGS_MAP_ASYNC)> &func);

//注册http请求参数是Json::Value类型的http api(可以支持多级嵌套的json参数对象)
void usr_api_regist(const std::string &api_path, const std::function<void(API_ARGS_JSON)> &func);
//注册http请求参数是Json::Value类型，但是可以异步回复的的http api
void usr_api_regist(const std::string &api_path, const std::function<void(API_ARGS_JSON_ASYNC)> &func);

//注册http请求参数是http原始请求信息的http api
void usr_api_regist(const std::string &api_path, const std::function<void(API_ARGS_STRING)> &func);
//注册http请求参数是http原始请求信息的异步回复的http api
void usr_api_regist(const std::string &api_path, const std::function<void(API_ARGS_STRING_ASYNC)> &func);

template<typename Args, typename First>
bool checkArgs(Args &args, const First &first) {
    return !args[first].empty();
}

template<typename Args, typename First, typename ...KeyTypes>
bool checkArgs(Args &args, const First &first, const KeyTypes &...keys) {
    return checkArgs(args, first) && checkArgs(args, keys...);
}


//检查http url中或body中或http header参数是否为空的宏
#define CHECK_ARGS(...)  \
    if(!checkArgs(allArgs,##__VA_ARGS__)){ \
        throw InvalidArgsException(u8"缺少参数"); \
    }

//检查http参数中是否附带secret密钥的宏，127.0.0.1的ip不检查密钥
#define CHECK_SECRET() \
    if(sender.get_peer_ip() != "127.0.0.1"){ \
        CHECK_ARGS("secret"); \
        if(api_secret != allArgs["secret"]){ \
            throw AuthException("secret error"); \
        } \
    }

//检查token
#define CHECK_TOKEN()                                                                                                \
    CHECK_ARGS("token");                                                                                    \
    if (!UsrToken::Instance().checkToken(allArgs["token"])) {                                                          \
        throw AuthException(u8"token 错误");                                                                           \
    }                                                                                                                  \
    if (!UsrToken::Instance().checkTokenTime(allArgs["token"])) {                                                      \
        throw AuthException(u8"token 过期");                                                                           \
    }                                                                                                                  \


//检查station
#define CHECK_STATION()                                                                                                \
    if (sender.get_peer_ip() != "127.0.0.1") {                                                                         \
        CHECK_TOKEN()                                                                                                  \
        CHECK_ARGS("station");                                                                                         \
        if (!(UsrToken::Instance().checkStation(allArgs["token"], allArgs["station"]))) {                              \
            throw AuthException(u8"用户没有站点权限");                                                                 \
        }                                                                                                              \
    }
    



void installWebApi();
void unInstallWebApi();

uint16_t openRtpServer(uint16_t local_port, const std::string &stream_id, int tcp_mode, const std::string &local_ip, bool re_use_port, uint32_t ssrc);
void connectRtpServer(const std::string &stream_id, const std::string &dst_url, uint16_t dst_port, const std::function<void(const toolkit::SockException &ex)> &cb);
bool closeRtpServer(const std::string &stream_id);
Json::Value makeMediaSourceJson(mediakit::MediaSource &media);
void getStatisticJson(const std::function<void(Json::Value &val)> &cb);
void addStreamProxy(const std::string &vhost, const std::string &app, const std::string &stream, const std::string &url, int retry_count,
                    const mediakit::ProtocolOption &option, int rtp_type, float timeout_sec,
                    const std::function<void(const toolkit::SockException &ex, const std::string &key)> &cb);
#endif //ZLMEDIAKIT_WEBAPI_H
