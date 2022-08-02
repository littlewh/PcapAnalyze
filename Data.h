//
// Created by admin on 2022/8/1.
//

#ifndef PCAPANALYZE_DATA_H
#define PCAPANALYZE_DATA_H
#include <iostream>
#include "Utilities.h"

class Data {
public:
    bool GetData(char *url, uint64_t offset, uint64_t &used_offset,uint64_t caplen);
    Utilities utilities;
    std::string message_data;
};

struct http_request_line{//请求报文的起始行
    std::string request_method;//请求方法
    std::string request_target;//请求目标
    std::string edition;//版本号
};
struct http_status_line{//响应报文的起始行
    std::string edition;//版本号
    std::string code;//状态码
    std::string reason;//原因
};
class HTTPRequestData:public Data{
public:
    void AnalyzeHTTPRequestData();
private:
    http_request_line httpRequestLine;//请求行
    std::string httpHeader;//请求头
    std::string httpBody;//请求体
};
class HTTPRespoundData:public Data{
public:
    void AnalyzeHTTPRespoundData();
private:
    http_status_line httpStatusLine;//状态行
    std::string httpHeader;//请求头
    std::string httpBody;//请求体
};

class DNSData:public Data{
public:
    DNSData(){
        map_Type[1] = "A";
        map_Class[1] = "IN";
    }
    virtual void AnalyzeDNSData(uint64_t payload) = 0;
    std::map<int,std::string > map_Type;
    std::map<int,std::string > map_Class;
//    static uint32_t pre;
private:

};

class DNSQueryData:public DNSData{
public:

    virtual void AnalyzeDNSData(uint64_t payload);

private:

};

class DNSRespoundData:public DNSData{
public:
    virtual void AnalyzeDNSData(uint64_t payload);
private:

};

#endif //PCAPANALYZE_DATA_H
