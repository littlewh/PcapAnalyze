//
// Created by admin on 2022/7/29.
//

#ifndef PCAPANALYZE_ARPHEADER_H
#define PCAPANALYZE_ARPHEADER_H
#include <cstdint>
#include <iostream>
#include <map>
#include "Utilities.h"

/* 共28字节 */

struct arp_header{
    uint8_t HardwareType[2];//硬件类型
    uint8_t ProtocolType[2];//协议类型
    uint8_t HardwareSize;//硬件地址长度
    uint8_t ProtocolSize;//协议地址长度
    uint8_t OpCode[2];//操作字段
    uint8_t SenderMacAddress[6];//发送者mac
    uint8_t SenderIPAddress[4];//发送方ip
    uint8_t TargetMacAddress[6];//目的地mac
    uint8_t TargetIPAddress[4];//目的地ip
};
class ArpHeader {
public:
    ArpHeader(){
        arpHeader = new arp_header();
        map_protocol[2048] = "IPv4";
        map_protocol[34525] = "IPv6";
        map_protocol[1] = "ICMP";
        map_protocol[2] = "IGMP";
        map_opcode[1] = "ARP request";
        map_opcode[2] = "ARP reply";
        map_opcode[3] = "RARP request";
        map_opcode[4] = "RARP reply";
    }
    bool GetArpHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeArpHeader();
    int protocol_type;
private:
    arp_header *arpHeader;
    std::map<int,std::string> map_protocol;
    std::map<int,std::string> map_opcode;
    Utilities utilities;
};


#endif //PCAPANALYZE_ARPHEADER_H
