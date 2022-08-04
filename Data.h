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
    std::string query_type_string;
    std::string cname;
    std::string address;
    std::string nameserver;
    std::string mailbox;
    bool message_type;//0 query   1 answer
};

struct session_elements_http{
    uint64_t source_ip;
    uint64_t destination_ip;
    uint64_t source_port;
    uint64_t destination_port;
    std::string method;
    std::string uri;//host+request
    std::string body;
    std::string edition;
    std::string code;
    std::string reason;
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
    http_request_line httpRequestLine;//请求行
    std::string httpHeader;//请求头
    std::string uri;
    std::string httpBody;//请求体
private:
};
class HTTPRespondData:public Data{
public:
    void AnalyzeHTTPRespondData();
    http_status_line httpStatusLine;//状态行
    std::string httpHeader;//请求头
    std::string httpBody;//请求体
private:

};

class DNSData:public Data{
public:
    DNSData(){
        map_Type[1] = "A:域名服务器地址";
        map_Type[2] = "NS:名字服务器";
        map_Type[5] = "CNAME:域名服务器别名";
        map_Type[6] = "SOA:授权标记一个区的开始";
        map_Type[11] = "WKS:服务定义主机提供的网络服务";
        map_Type[12] = "PTR:指针把IP地址转化为域名";
        map_Type[28] = "AAAA:IPv6地址";
        map_Type[255] = "ANY：对所有记录的请求";
        map_Class[1] = "IN:互联网地址";
    }
    virtual void AnalyzeDNSData(char *url, uint64_t offset, uint64_t &used_offset,uint64_t payload,std::map<uint64_t,std::deque<session_elements>> &DNS_session,uint64_t TransactionID) = 0;
    std::map<int,std::string > map_Type;
    std::map<int,std::string > map_Class;
    std::string context;
    std::string query_type_string;
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
    std::string nameserver;
    std::string mailbox;
private:

};

#endif //PCAPANALYZE_DATA_H
