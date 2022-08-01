//
// Created by admin on 2022/8/1.
//

#ifndef PCAPANALYZE_DATA_H
#define PCAPANALYZE_DATA_H
#include <iostream>

class Data {
public:
    bool GetHttpData(char *url, uint64_t offset, uint64_t &used_offset,uint64_t caplen);

private:
    std::string host;
    std::string url;
};


#endif //PCAPANALYZE_DATA_H
