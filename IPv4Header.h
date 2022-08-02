//
// Created by admin on 2022/7/28.
//

#ifndef PCAPANALYZE_IPV4HEADER_H
#define PCAPANALYZE_IPV4HEADER_H

#include <cstdint>
#include <iostream>
#include <map>
#include "Utilities.h"

/*共20字节*/

struct ipv4_header{
    uint8_t VersionAndIHL;//版本和头部长度
    uint8_t TypeOfService;//服务类型
    uint8_t TotalLength[2];//总长度
    uint8_t Identification[2];//标识
    uint8_t FlagsAndFragementOffset[2];//标志和片偏移
    uint8_t TimeToLive;//生存时间
    uint8_t Protocol;//协议
    uint8_t HeaderChecksum[2];//头部校验和
    uint8_t SourceAddress[4];//源IP
    uint8_t DestinationAddress[4];//目的IP
};
class IPv4Header {
public:
    IPv4Header(){
        ipv4Header = new ipv4_header();
        map_protocol[1] = "ICMP";
        map_protocol[2] = "IGMP";
        map_protocol[4] = "IP";
        map_protocol[6] = "TCP";
        map_protocol[17] = "UDP";
        map_protocol[47] = "GRE";
        map_protocol[89] = "OSPF";
    }
    bool GetIPHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    // IP解析头
    void AnalyzeIPHeader(uint64_t &used_offset,uint64_t &ipTotalLen);
    int ipProtocolType;
private:
    ipv4_header *ipv4Header;
    std::map<uint8_t ,std::string> map_protocol;
    Utilities utilities;
};


#endif //PCAPANALYZE_IPV4HEADER_H
