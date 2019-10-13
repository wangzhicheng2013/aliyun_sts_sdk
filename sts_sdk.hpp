#ifndef STS_SDK_HPP
#define STS_SDK_HPP
#include "curlclient.hpp"
#include "utility.hpp"
#include "json/json.h"
struct Credentials {
    std::string AccessKeySecret;
    std::string AccessKeyId;
    std::string Expiration;
    std::string SecurityToken;
};
class Sts_Sdk {
public:
    Sts_Sdk() = default;
    Sts_Sdk(const Sts_Sdk &) = delete;
    Sts_Sdk & operator = (const Sts_Sdk &) = delete;
    virtual ~Sts_Sdk() = default;
public:
    bool init() {
        return curlclient_.init();
    }
    void get_credentials(Credentials &credentials) {
        set_timestamp();
        set_signatureNonce();
        set_RoleSessionName();
        if (false == generate_certain_url()) {
            return;
        }
	//sts_url_ = "https://sts.aliyuncs.com/AccessKeyId=LTAI4FdyyA3S62nWuxiqQWBW&Action=AssumeRole&Format=json&RoleArn=acs:ram::1825170684977218:role/wangbin3&RoleSessionName=Alice0&SignatureMethod=HMAC-SHA1&SignatureNonce=23272e40-cf7a-0037-2329-100000000000&SignatureVersion=1.0&Timestamp=2019-10-12T23:58:40Z&Version=2015-04-01&Signature=WawgtIl7sXYWR1s4n9NBwpZDvS4%3D";
	//sts_url_ = "https://sts.aliyuncs.com/?AccessKeyId=LTAI4FdyyA3S62nWuxiqQWBW&Action=AssumeRole&Format=json&RoleArn=acs:ram::1825170684977218:role/wangbin3&RoleSessionName=Alice0&SignatureMethod=HMAC-SHA1&SignatureNonce=23272e40-cf7a-0037-2329-300000000000&SignatureVersion=1.0&Timestamp=2019-10-12T23:59:30Z&Version=2015-04-01&Signature=ZNfUrgOOaU%2FwhFU9pqKyhJ%2FuVhU%3D";
        curlclient_.curl_get(sts_url_.c_str(), response_str_, http_code_);
        parse_sts_response(response_str_, credentials);
    }
    void set_AccessKeyId(const std::string &key) {
        AccessKeyId_ = key;
    }
    void set_AccessKeySecret(const std::string &key) {
        AccessKeySecret_ = key;
    }
    void set_RoleArn(const std::string &roleArn) {
        RoleArn_ = roleArn;
    }
    bool parse_sts_response(const std::string response_str, Credentials &credentials) {
        Json::Value value;
        Json::Reader reader;
        if (false == reader.parse(response_str, value)) {
            return false;
        }
        Json::Value Credentials = value["Credentials"];
        if (true == Credentials.empty()) {
            return false;
        }
        if (false == Credentials["AccessKeySecret"].empty()) {
            credentials.AccessKeySecret = Credentials["AccessKeySecret"].asString();
        }
        if (false == Credentials["AccessKeyId"].empty()) {
            credentials.AccessKeyId = Credentials["AccessKeyId"].asString();
        }
        if (false == Credentials["Expiration"].empty()) {
            credentials.Expiration = Credentials["Expiration"].asString();
        }
        if (false == Credentials["SecurityToken"].empty()) {
            credentials.SecurityToken = Credentials["SecurityToken"].asString();
        }
        return true;
    }
    inline long get_response_code() const {
        return http_code_;
    }
    inline void get_response_string(std::string &str) const {
        str = response_str_;
    }
    inline void get_sts_url(std::string &str) const {
        str = sts_url_;
    }
private:
    inline void set_timestamp() {
        Utility::generate_utc_time(timestamp_);
    }
    void set_signatureNonce() {
        Utility::generate_uuid(signatureNonce_);
    }
    void set_RoleSessionName() {
        static long count = 0;
        char buf[64] = "";
        snprintf(buf, sizeof(buf), "Alice%ld", count);
        RoleSessionName_ = buf;
        count = (count + 1) % 100000000;
    }
    bool generate_certain_url() {
        char buf[1024] = "";
        snprintf(buf, sizeof(buf), 
            "AccessKeyId=%s&Action=%s&Format=%s&RoleArn=%s&RoleSessionName=%s&SignatureMethod=%s&SignatureNonce=%s&SignatureVersion=%s&Timestamp=%s&Version=%s",
            AccessKeyId_.c_str(), 
            action_.c_str(),
            format_.c_str(),
            RoleArn_.c_str(),
            RoleSessionName_.c_str(),
            SignatureMethod_.c_str(),
            signatureNonce_.c_str(),
            SignatureVersion_.c_str(),
            timestamp_.c_str(),
            version_.c_str());
        char result[1024] = "";
        if (Utility::url_encode(buf, strlen(buf), result, sizeof(result)) <= 0) {
            return false;
        }
        std::string tmp = "GET&%2F&";
        tmp += result;
        Utility::generate_signature(AccessKeySecret_.c_str(), tmp.c_str(), signature_);
        memset(result, 0, sizeof(result));
        Utility::url_encode1(signature_.c_str(), signature_.size(), result, sizeof(result));
        sts_url_ = end_point_;
        sts_url_ += "/?";
        sts_url_ += buf;
        sts_url_ += "&Signature=";
        sts_url_ += result;
        return true;
    }
private:
    long http_code_ = 0;
    std::string response_str_;
    std::string end_point_ = "https://sts.aliyuncs.com";
    std::string action_ = "AssumeRole";
    std::string format_ = "json";
    std::string version_ = "2015-04-01";
    std::string timestamp_;
    std::string signatureNonce_;
    std::string AccessKeyId_;
    std::string AccessKeySecret_;
    std::string SignatureMethod_ = "HMAC-SHA1";
    std::string SignatureVersion_ = "1.0";
    std::string signature_;
    std::string RoleArn_;
    std::string RoleSessionName_;
    std::string sts_url_;
    CurlClient curlclient_;
};

#endif
