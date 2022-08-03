//
// Created by admin on 2022/8/1.
//

#ifndef PCAPANALYZE_UDPHEADER_H
#define PCAPANALYZE_UDPHEADER_H
#include <cstdint>
#include "Utilities.h"

/*共8字节*/

struct udp_header{
    uint8_t SourcePort[2];//源端口
    uint8_t DestinationPort[2];//目的端口
    uint8_t Length[2];//长度
    uint8_t CheckSum[2];//校验和
};

class UDPHeader {
public:
    UDPHeader(){
        udpHeader = new udp_header();
    }
    bool GetUDPHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeUDPHeader(uint64_t &payload);
    uint32_t destination_port;
    uint32_t source_port;
private:
    udp_header *udpHeader;
    Utilities utilities;
};


#endif //PCAPANALYZE_UDPHEADER_H
