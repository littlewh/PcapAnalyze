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
        map_qr[0] = "查询报文";
        map_qr[1] = "响应报文";

        map_code[0] = "标准查询";
        map_code[1] = "反向查询";
        map_code[2] = "服务器状态请求";

        map_aa[0] = "不是权威服务器";
        map_aa[1] = "权威服务器";

        map_tc[0] = "不可截断的";
        map_tc[1] = "可截断的";

        map_rd[0] = "迭代查询";
        map_rd[1] = "递归查询";

        map_ra[0] = "不可用递归查询";
        map_ra[1] = "可用递归查询";

        map_rcode[0] = "没有错误";
        map_rcode[1] = "报文格式错误";
        map_rcode[2] = "域名服务器失败";
        map_rcode[3] = "名字错误";
        map_rcode[4] = "查询类型不支持";
        map_rcode[5] = "拒绝";
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
