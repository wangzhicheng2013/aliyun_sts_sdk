#ifndef UTILITY_HPP
#define UTILITY_HPP
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include <string>
#include <map>
#include "openssl/hmac.h"
#include "base64.h"
#include "sole.hpp"
class Utility {
public:
    /*
     * 生成sts消息签名
     */
    static void generate_signature(const char *secret_key, const char *plaintext, std::string &ciphertext) {
        uint8_t hmac_sha1[EVP_MAX_MD_SIZE] = {0};
        uint32_t hmac_sha1_len = EVP_MAX_MD_SIZE;
        HMAC(EVP_sha1(), secret_key, strlen(secret_key), (const uint8_t*)plaintext, strlen(plaintext), hmac_sha1, &hmac_sha1_len);
        const int size = (EVP_MAX_MD_SIZE << 1);
        char signature[size + 1] = {0};
        int signature_len = size;
        Base64Encode(hmac_sha1, hmac_sha1_len, signature, &signature_len);
        ciphertext = signature;
    }
    static inline void generate_uuid(std::string &uuid) {
        uuid = sole::uuid0().str();
    }
    /*
     * 从url获取key与val，例如https://www.baidu.com?A=1&B=2，则key_val_map为{<A,1>, <B,2>}
     */
    static void get_url_key_val(const char *uri, std::map<std::string, std::string>&key_val_map) {
        const char *p = uri;
        while (*p) {
            if('?' == *p) {
                break;
            }
            p++;
        }
        if(0 == *p) {
            return;
        }
        char tmp[1024] = "";
        int loop = 0;
        bool Get = false;
        std::vector<std::string>keys;
        std::vector<std::string>values;
        while (*p) {
            if (*(p + 1) && !Get) {
			    sscanf(p + 1, "%[^= | &]", tmp);
			    if (strcmp(tmp, "")) {
				    Get = true;
				    if (!loop) {
					    keys.emplace_back(tmp);
				    }
				    else {
					    values.emplace_back(tmp);
				    }
			    }
		    }
            p++;
            if (0 == *p) {
                break;
            }
            if (('=' == *p) || ('&' == *p)) {
                if ('=' == *p) {
                    loop = 1;
                }
                else {
                    loop = 0;
                }
                Get = false;
            }
        }
        if (keys.size() != values.size()) {
            return;
        }
        int size = keys.size();
        for (int i = 0;i < size;i++) {
            key_val_map.insert(make_pair(keys[i], values[i]));
        }
    }
    /*
     * 对url进行编码，特殊字符按照sts官网要求进行编码
     */
    static int url_encode(const char *str, const int strSize, char *result, const int resultSize) {
        int i;
        int j = 0;  //for result index
        char ch;
        if ((NULL == str) || (NULL == result) || (strSize <= 0) || (resultSize <= 0)) {
            return 0;
        }
        for (i = 0;(i < strSize) && (j < resultSize);++i) {
            ch = str[i];
            if (isupper(ch) || islower(ch) || isdigit(ch)) {
                result[j++] = ch;
                continue;
            }
            if (ch == ' ') {
                result[j++] = '+';
                continue;
            }
            if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
                result[j++] = ch;
                continue;
            }
            if (ch == ':'|| ch == '/') {
                if (j + 5 < resultSize) {
                    sprintf(result+j, "%%25%02X", (unsigned char)ch);
                    j += 5;
                }
            }
            else if (j + 3 < resultSize) {
                sprintf(result+j, "%%%02X", (unsigned char)ch);
                j += 3;
            }
            else {
                return 0;
            }
        }
        result[j] = '\0';
        return j;
    }
    /*
     * 对url进行编码，特殊字符按照sts官网要求进行编码
     */
    static int url_encode1(const char *str, const int strSize, char *result, const int resultSize) {
        int i;
        int j = 0;  //for result index
        char ch;
        if ((NULL == str) || (NULL == result) || (strSize <= 0) || (resultSize <= 0)) {
            return 0;
        }
        for (i = 0;(i < strSize) && (j < resultSize);++i) {
            ch = str[i];
            if (isupper(ch) || islower(ch) || isdigit(ch)) {
                result[j++] = ch;
                continue;
            }
            if (ch == ' ') {
                result[j++] = '+';
                continue;
            }
            if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
                result[j++] = ch;
                continue;
            }
            else if (j + 3 < resultSize) {
                sprintf(result+j, "%%%02X", (unsigned char)ch);
                j += 3;
            }
            else {
                return 0;
            }
        }
        result[j] = '\0';
        return j;
    }
    /*
     * 生成当前utc时间 形如:2019-10-11T09:28:00Z
     */
    static inline void generate_utc_time(std::string &utc_time) {
        char buf[64] = {0};
        time_t now;
        time(&now);
        struct tm *ttm = gmtime(&now);
        snprintf(buf, sizeof(buf), "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ", ttm->tm_year + 1900, 
                                                                      ttm->tm_mon + 1, 
                                                                      ttm->tm_mday,
                                                                      ttm->tm_hour,
                                                                      ttm->tm_min,
                                                                      ttm->tm_sec);

        utc_time = buf;
    }
    /*
     * 将utc时间转为本地时间
     */
    static void convert_to_localtime(const std::string &utc_time, std::string &local_time) {
        std::string str = utc_time;
        //struct tm unixdate = {0};
        struct tm unixdate;
        strptime(str.c_str(), "%Y-%m-%dT%H:%M:%SZ", &unixdate);
        time_t fakeUnixTime = mktime(&unixdate); 
        struct tm *fakeDate = gmtime(&fakeUnixTime);
        int32_t nOffset = fakeDate->tm_hour - unixdate.tm_hour;
        if (nOffset > 12) {
            nOffset = 24 - nOffset;
        }
        fakeUnixTime = fakeUnixTime - nOffset * 3600;

        char buf[64] = {0};
        struct tm *ttm = gmtime(&fakeUnixTime);
        snprintf(buf, sizeof(buf), "%.4d-%.2d-%.2d %.2d:%.2d:%.2d", ttm->tm_year + 1900, 
                                                                      ttm->tm_mon + 1, 
                                                                      ttm->tm_mday,
                                                                      ttm->tm_hour,
                                                                      ttm->tm_min,
                                                                      ttm->tm_sec);

        local_time = buf;
    }
};

#endif
