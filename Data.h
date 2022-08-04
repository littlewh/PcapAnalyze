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

struct http_request_line{//�����ĵ���ʼ��
    std::string request_method;//���󷽷�
    std::string request_target;//����Ŀ��
    std::string edition;//�汾��
};
struct http_status_line{//��Ӧ���ĵ���ʼ��
    std::string edition;//�汾��
    std::string code;//״̬��
    std::string reason;//ԭ��
};
class HTTPRequestData:public Data{
public:
    void AnalyzeHTTPRequestData();
private:
    http_request_line httpRequestLine;//������
    std::string httpHeader;//����ͷ
    std::string httpBody;//������
};
class HTTPRespondData:public Data{
public:
    void AnalyzeHTTPRespondData();
private:
    http_status_line httpStatusLine;//״̬��
    std::string httpHeader;//����ͷ
    std::string httpBody;//������
};

class DNSData:public Data{
public:
    DNSData(){
        map_Type[1] = "A:������������ַ";
        map_Type[5] = "CNAME:��������������";
        map_Type[6] = "SOA:Ȩ��DNS�����ʼλ��";
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
