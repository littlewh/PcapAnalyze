//
// Created by admin on 2022/7/27.
//

#ifndef PCAPANALYZE_PACKETHEADER_H
#define PCAPANALYZE_PACKETHEADER_H


#include <fstream>
#include <iostream>
#include <cstdint>
#include <iostream>
#include <map>
/*packetheader共4*4=16个字节*/

struct packet_header{
    uint8_t char_timestamp_high[4];//时间戳高位
    uint8_t char_timestamp_low[4];//时间戳低位
    uint8_t char_caplen[4];//当前数据区长度
    uint8_t char_len[4];//离线数据长度
};
class PacketHeader {
public:
    PacketHeader(){
        packetHeader = new packet_header();
    }

    bool GetPacketHeader(char *url,uint64_t offset);//获取Header数据
    long long AnalyzePacketHeader(bool pcapFlag);//分析Header数据

private:

    packet_header *packetHeader;
};


#endif //PCAPANALYZE_PACKETHEADER_H
