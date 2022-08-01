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

private:
    void KMP_getnext(uint64_t tar_len,uint64_t data_len,int next[]);
    void KMP();
};


#endif //PCAPANALYZE_UTILITIES_H
