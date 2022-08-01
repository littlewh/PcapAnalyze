//
// Created by admin on 2022/8/1.
//

#include "Data.h"
#include "Utilities.h"
/*
 * 获取HTTP数据
 */
bool Data::GetHttpData(char *url, uint64_t offset, uint64_t &used_offset, uint64_t caplen) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取HTTPData时打开文件失败");
        return false;
    }
    else {
        offset += used_offset;//加上Mac IP tcp偏移
        fseek(fp,offset,SEEK_SET);
        uint64_t reallyLen = caplen - used_offset;
        char data[reallyLen];
        fread(data,reallyLen,1,fp);
        used_offset += reallyLen;
        fclose(fp);

        printf("%s\n",data);


        return true;
    }
}