//
// Created by admin on 2022/8/1.
//

#ifndef PCAPANALYZE_UTILITIES_H
#define PCAPANALYZE_UTILITIES_H
#include <cstdint>
#include <map>

class Utilities {
public:
    long long DisplayArray(int cnt,uint8_t addr[]);
    int DisplayElement(uint8_t element);
    void BackSpace(int number);
    uint64_t Find_KMP(char data_string[],char target_string[]);
    bool inputHeader(char *url, uint64_t offset, uint64_t &used_offset,uint64_t len,void *object);
    std::string findItemInData(std::string item_start,std::string item_end,std::string data);
    uint64_t DNSAnswerHeader(uint8_t data[],uint64_t &length,uint64_t &payload,std::map<int,std::string > &map_Class);
    uint64_t HTTPHashFunction(uint32_t source_ip,uint32_t destination_ip,uint32_t source_port,uint32_t destination_port);
private:
    void KMP_getnext(uint64_t tar_len,uint64_t data_len,int next[]);
    void KMP();
};


#endif //PCAPANALYZE_UTILITIES_H
