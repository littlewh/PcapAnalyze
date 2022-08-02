//
// Created by admin on 2022/8/2.
//

#ifndef PCAPANALYZE_DNSHEADER_H
#define PCAPANALYZE_DNSHEADER_H

#include <cstdint>
#include "Utilities.h"
/* 共12字节*/
struct dns_header{
    uint8_t TransactionID[2];//事务id
    uint8_t Flags[2];//标志
    uint8_t Questions[2];//问题计数
    uint8_t AnswerRRs[2];//回答资源记录数
    uint8_t AuthorityRRs[2];//权威名称服务器计数
    uint8_t AdditionalRRs[2];//附加资源记录数
};
class DNSHeader {
public:
    DNSHeader(){
        dnsHeader = new dns_header();
    }
    bool GetDNSHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeDNSHeader(uint64_t &ipTotalLen);
    bool dns_Type;//0是请求，1是响应
private:
    dns_header *dnsHeader;
    Utilities utilities;
};


#endif //PCAPANALYZE_DNSHEADER_H
