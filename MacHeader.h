//
// Created by admin on 2022/7/28.
//

#ifndef PCAPANALYZE_MACHEADER_H
#define PCAPANALYZE_MACHEADER_H
#include <cstdint>
#include <fstream>
#include <map>
#include "Utilities.h"

/*共14字节*/

struct mac_header{
    uint8_t DesTinationMacAddress[6];//目的mac
    uint8_t SourceMacAddress[6];//源mac
    uint8_t MacType[2];//上层协议类型
};
class MacHeader {
public:
    MacHeader(){
        macHeader = new mac_header();
        map_type[2048] = "IPv4";
        map_type[2054] = "ARP";
        map_type[33079] = "Novell IPX";
        map_type[34525] = "IPv6";
        map_type[34827] = "PPP";
    }
    bool GetMacHeader(char *url,uint64_t offset,uint64_t &used_offset);//获取Header数据
    void AnalyzeMacHeader();

    uint32_t MacTypeflag;
private:
    mac_header *macHeader;
    std::map<long,std::string> map_type;
    Utilities utilities;
};


#endif //PCAPANALYZE_MACHEADER_H
