//
// Created by admin on 2022/8/1.
//

#ifndef PCAPANALYZE_UDPHEADER_H
#define PCAPANALYZE_UDPHEADER_H
#include <cstdint>
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
    bool GetTCPHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeTCPHeader();
    int destination_port;
private:
    udp_header *udpHeader;
};


#endif //PCAPANALYZE_UDPHEADER_H
