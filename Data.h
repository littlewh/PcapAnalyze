//
// Created by admin on 2022/8/1.
//

#ifndef PCAPANALYZE_DATA_H
#define PCAPANALYZE_DATA_H
#include <iostream>
#include <deque>
#include "Utilities.h"

struct session_elements{
    uint32_t source_ip;
    uint32_t destination_ip;
    uint32_t source_port;
    uint32_t destination_port;
    std::string context;
    uint64_t query_type;
    std::string cname;
    std::string address;
    bool message_type;//0 query   1 answer
};
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
class HTTPRespondData:public Data{
public:
    void AnalyzeHTTPRespondData();
private:
    http_status_line httpStatusLine;//状态行
    std::string httpHeader;//请求头
    std::string httpBody;//请求体
};

class DNSData:public Data{
public:
    DNSData(){
        map_Type[1] = "A:域名服务器地址";
        map_Type[5] = "CNAME:域名服务器别名";
        map_Type[6] = "SOA:权威DNS域的起始位置";
        map_Type[28] = "AAAA:IPv6 Addrrss";
        map_Class[1] = "IN";
    }
    virtual void AnalyzeDNSData(char *url, uint64_t offset, uint64_t &used_offset,uint64_t payload,std::map<uint64_t,std::deque<session_elements>> &DNS_session,uint64_t TransactionID) = 0;
    std::map<int,std::string > map_Type;
    std::map<int,std::string > map_Class;
    std::string context;
    uint64_t query_type;
//    static uint32_t pre;
private:

};

class DNSQueryData:public DNSData{
public:

    virtual void AnalyzeDNSData(char *url, uint64_t offset, uint64_t &used_offset,uint64_t payload,std::map<uint64_t,std::deque<session_elements>> &DNS_session,uint64_t TransactionID);

private:

};

class DNSRespondData:public DNSData{
public:
    virtual void AnalyzeDNSData(char *url, uint64_t offset, uint64_t &used_offset,uint64_t payload,std::map<uint64_t,std::deque<session_elements>> &DNS_session,uint64_t TransactionID);
    std::string cname;
    std::string address;
    std::string mailbox;
private:

};

#endif //PCAPANALYZE_DATA_H
