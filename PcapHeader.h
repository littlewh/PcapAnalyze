//
// Created by admin on 2022/7/26.
//

#ifndef PCAPANALYZE_PCAPHEADER_H
#define PCAPANALYZE_PCAPHEADER_H
/*packetheader共4*5 + 2*2=24个字节*/

#include <map>
#include <cstdint>
#include <iostream>

struct pcap_header{
    uint8_t char_magic[4];//标识文件开头 大小端
    uint8_t char_major[2];//主要版本号
    uint8_t char_minor[2];//次要版本号
    uint8_t char_thiszone[4];//标准时间
    uint8_t char_sigfigs[4];//时间戳精度
    uint8_t  char_snap_len[4];//最大的存储长度
    uint8_t char_linktype[4];//链路类型
};
class PcapHeader{
public:
    PcapHeader(){
        pcapHeader = new pcap_header();
        map_linktype[0] = "BSD loopback devices, except for later OpenBSD ";
        map_linktype[1] = "Ethernet, and Linux loopback devices ";
        map_linktype[6] = "802.5 Token Ring";
        map_linktype[7] = "ARCnet ";
        map_linktype[8] = "SLIP ";
        map_linktype[9] = "PPP";
        map_linktype[10] = "FDDI ";
        map_linktype[100] = "LLC/SNAP-encapsulated ATM";
        map_linktype[101] = "“raw IP”, with no link ";
        map_linktype[102] = "BSD/OS SLIP ";
        map_linktype[103] = "BSD/OS PPP ";
        map_linktype[104] = "Cisco HDLC ";
        map_linktype[105] = "802.11 ";
        map_linktype[108] = " later OpenBSD loopback devices (with the AF_value in network byte order) ";
        map_linktype[113] = "special Linux “cooked” capture ";
        map_linktype[114] = "LocalTalk ";

    }
    bool GetPcapHeader(char *url,uint64_t offset);//获取Header数据
    bool AnalyzePcapHeader();//分析Header数据
    int LinkTypeFlag;

private:
    pcap_header *pcapHeader;
    std::map<long,std::string> map_linktype;

};
#endif //PCAPANALYZE_PCAPHEADER_H
