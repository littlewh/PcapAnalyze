//
// Created by admin on 2022/7/28.
//

#ifndef PCAPANALYZE_TCPHEADER_H
#define PCAPANALYZE_TCPHEADER_H
#include <cstdint>
#include <iostream>
#include <map>
#include "Utilities.h"

/*共20个字节*/

struct tcp_header{
    uint8_t SourcePort[2];//源端口
    uint8_t DestinationPort[2];//目的端口
    uint8_t SequenceNumber[4];//序号
    uint8_t AcknowledgmentNumber[4];//确认序号
    uint8_t OffsetReserveFlag[2];//偏移保留标志
    uint8_t Window[2];//窗口大小
    uint8_t CheckSum[2];//校验和
    uint8_t UrgentPointer[2];//指针
};
class TCPHeader {
public:
    TCPHeader(){
        tcpHeader = new tcp_header();
    }
    bool GetTCPHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeTCPHeader(uint64_t &used_offset,uint64_t &payload);
    int tcp_flags;
    int destination_port;
    int source_port;
private:
    tcp_header *tcpHeader;
    Utilities utilities;
};


#endif //PCAPANALYZE_TCPHEADER_
// H
