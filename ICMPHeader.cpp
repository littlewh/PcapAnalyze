//
// Created by admin on 2022/7/29.
//

#include <cstdio>
#include <iostream>
#include "ICMPHeader.h"

bool ICMPHeader::GetICMPHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取ICMPHeader时打开文件失败");
        return false;
    }
    else {
        offset += used_offset;//加上Mac IP偏移
        fseek(fp,offset,SEEK_SET);
        fread(icmpHeader,8,1,fp);
        used_offset += 8;
        fclose(fp);
        return true;
    }
}

void ICMPHeader::AnalyzeICMPHeader() {

}