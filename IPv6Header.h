//
// Created by admin on 2022/7/29.
//

#ifndef PCAPANALYZE_IPV6HEADER_H
#define PCAPANALYZE_IPV6HEADER_H
#include <cstdint>
#include <iostream>
#include <map>
/*共40字节*/

struct ipv6_header{
    uint8_t VersionAndTrafiicHigh;//版本号和流量类型高4位
    uint8_t TrafiicLowAndFlowHigh;//流量类型低4位和流标签高4位
    uint8_t FlowLable[2];//流标签低16位
    uint8_t PayloadLength[2];//负载长度
    uint8_t NextHeader;//下一报头
    uint8_t HopLimit;//生存时间
    uint8_t SourceAddress[16];//源地址
    uint8_t DestinationAddress[16];//目的地址
};
class IPv6Header {
public:
    IPv6Header(){
        ipv6Header = new ipv6_header();
        map_nextheader[43] = "路由报头";
        map_nextheader[44] = "分段报头";
        map_nextheader[1] = "ICMPv4";
        map_nextheader[2] = "IGMPv4";
        map_nextheader[6] = "TCP";
        map_nextheader[17] = "UDP";
        map_nextheader[58] = "ICMPv6";
        map_nextheader[88] = "EIGRP";
        map_nextheader[89] = "OSPFv3";
    }
    bool GetIPHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeIPHeader();
    int nextHeader;
private:
    ipv6_header *ipv6Header;
    std::map<int,std::string> map_nextheader;
};


#endif //PCAPANALYZE_IPV6HEADER_H
