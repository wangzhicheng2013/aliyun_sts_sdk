#ifndef CURL_CLIENT_HPP
#define CURL_CLIENT_HPP
#include <string>
#include "curl/curl.h"
#include "outstream.h"
// 使用libcurl封装为curl客户端，提供restful GET操作
class CurlClient {
public:
    CurlClient() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    CurlClient(const CurlClient &) = delete;
    CurlClient & operator = (const CurlClient &) = delete;
    ~CurlClient() {
        if (nullptr != curl_) {
            curl_easy_cleanup(curl_);
            curl_ = nullptr;
        }
        curl_global_cleanup();
    }
public:
    bool init() {
        curl_ = curl_easy_init();
        if (nullptr == curl_) {
            return false;
        }
        // 主机名与证书校验
        if (CURLE_OK != curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L)) {
            return false;
        }
        if (CURLE_OK != curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L)) {
            return false;
        }

        curl_init_succ = true;
        return true;
    }
    /*
     * 向服务器发送get请求，并返回响应字符串
     */
    bool curl_get(const char *url, std::string &response_string, long &http_code) {
        if (false == curl_init_succ) {
            return false;
        }
        outstream_t data;
        outstream_init(&data);

        curl_easy_setopt(curl_, CURLOPT_URL, url);
        curl_easy_setopt(curl_, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, on_http_content);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &data);

        int ret = curl_easy_perform(curl_);
        if (ret != CURLE_OK) {
            return false;
        }
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
        response_string.assign((char*)data.data);
        FREEIF(data.data);
        return true;
    }
private:
    static size_t on_http_content(void *buffer, size_t unused, size_t size, void *userp) {
        outstream_t *content = static_cast<outstream_t *>(userp);
        if (nullptr == content) {
            return -1;
        }
        int last_char = outstream_lastchar(content);
        if ('\0' == last_char) {
            content->data_len--;
        }
        outstream_writebuf(content, (const char*)buffer, (int)size);
        outstream_writechar(content, '\0');
        return size;
    }
private:
    CURL *curl_ = nullptr;
    bool curl_init_succ = false;
};
#endif
