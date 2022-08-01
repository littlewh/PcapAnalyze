//
// Created by admin on 2022/7/29.
//

#ifndef PCAPANALYZE_ICMPHEADER_H
#define PCAPANALYZE_ICMPHEADER_H
#include <cstdint>
#include <map>
/* 共8个字节 */

struct icmp_header{
    uint8_t Type;//类型
    uint8_t Code;//代码
    uint8_t CheckSum[2];//校验和
    uint8_t Identifier[2];//标识符
    uint8_t SequenceNumber[2];//序列号
};
class ICMPHeader {
public:
    ICMPHeader(){
        errorFlag = false;
        icmpHeader = new icmp_header();
        map_type[0] = "应答";
        map_type[3] = "终点不可达";
        map_type[5] = "重定向";
        map_type[8] = "回送请求";
        map_type[11] = "时间超过";
        map_type[12] = "参数问题";
        map_type[13] = "时间戳请求";
        map_type[14] = "时间戳回答";

        map_code[0] = "回显";
        map_code[1] = "主机";
        map_code[2] = "协议";
        map_code[3] = "端口";
    }
    bool GetICMPHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeICMPHeader();
    bool errorFlag;
private:
    icmp_header *icmpHeader;
    std::map<int,std::string> map_type;
    std::map<int,std::string> map_code;
};


#endif //PCAPANALYZE_ICMPHEADER_H
