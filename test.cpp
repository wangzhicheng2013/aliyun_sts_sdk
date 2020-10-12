#include <iostream>
#include "sts_sdk.hpp"
int main() {
    Sts_Sdk sdk;
    if (false == sdk.init()) {
        return -1;
    }
    for (int i = 0;i < 1000;i++) {
        Credentials credentials;
        std::string response_str = "{\"RequestId\": \"A\",\"AssumedRoleUser\":{\"AssumedRoleId\": \"1\",\"Arn\": \"lice\"},\"Credentials\": {\"AccessKeySecret\": \"AA\",\"AccessKeyId\": \"BB\",\"Expiration\":\"CC\",\"SecurityToken\": \"DD\"}}";
        sdk.parse_sts_response(response_str, credentials);
        std::cout << credentials.AccessKeyId << std::endl;
        std::cout << credentials.AccessKeySecret << std::endl;
        std::cout << credentials.Expiration << std::endl;
        std::cout << credentials.SecurityToken << std::endl;
        std::string AccessKeyId = "LTAI4FdyyA3S62nWuxiqQWBW123";
        std::string AccessKeySecret = "TmjUSpsLMQAexqWN0HL8RYSxhkVYvM&123";
        std::string RoleArn = "acs:ram::1825170684977218:role/xxx3123";
        sdk.set_AccessKeyId(AccessKeyId);
        sdk.set_AccessKeySecret(AccessKeySecret);
        sdk.set_RoleArn(RoleArn);
        sdk.get_credentials(credentials);
        std::string str;
        sdk.get_response_string(str);
        std::cout << str << std::endl;
        sdk.get_sts_url(str);
        std::cout << str << std::endl;
        std::cout << credentials.AccessKeyId << std::endl;
        std::cout << credentials.AccessKeySecret << std::endl;
        std::cout << credentials.Expiration << std::endl;
        std::cout << credentials.SecurityToken << std::endl;
        if (sdk.get_response_code() != 200) {
            std::cerr << "response error from sts...!" << std::endl;
            exit(-1);
        }
    }
    return 0;
}
