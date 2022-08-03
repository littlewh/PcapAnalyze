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
        map_qr[0] = "request";
        map_qr[1] = "response";

        map_code[0] = "stand query";
        map_code[1] = "reserve query";
        map_code[2] = "status request";

        map_aa[0] = "authority";
        map_aa[1] = "not authority";

        map_tc[0] = "not truncated";
        map_tc[1] = "truncated";

        map_rd[0] = "do not recursively";
        map_rd[1] = "do recursively";

        map_ra[0] = "not apply recursively";
        map_ra[1] = "apply recursively";

        map_rcode[0] = "no error";
        map_rcode[1] = "Format Error";
        map_rcode[2] = "Server failure";
        map_rcode[3] = "Name Error";
        map_rcode[4] = "NOt Implemented";
        map_rcode[5] = "Refused";
    }
    bool GetDNSHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeDNSHeader(uint64_t &ipTotalLen);
    bool dns_Type;//0是查询，1是响应
    uint64_t TransactionID;//key
private:
    dns_header *dnsHeader;
    Utilities utilities;
    std::map<int,std::string> map_qr;
    std::map<int,std::string> map_code;
    std::map<int,std::string> map_aa;
    std::map<int,std::string> map_tc;
    std::map<int,std::string> map_rd;
    std::map<int,std::string> map_ra;
    std::map<int,std::string> map_rcode;
};


#endif //PCAPANALYZE_DNSHEADER_H
