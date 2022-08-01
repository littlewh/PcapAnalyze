//
// Created by admin on 2022/7/28.
//

#include <iostream>
#include "MacHeader.h"
bool::MacHeader::GetMacHeader(char *url,uint64_t offset,uint64_t &used_offset){
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取MacHeader时打开文件失败");
        return false;
    }
    else {
        offset += used_offset;
        fseek(fp,offset,SEEK_SET);
        fread(macHeader,14,1,fp);
        used_offset += 14;
        fclose(fp);
        return true;
    }
}

void::MacHeader::AnalyzeMacHeader(){
    printf("Destination:");
    for (int i = 0;i < 6;i++){
        printf("%02x",macHeader->DesTinationMacAddress[i]);
        if(i < 5){
            printf(":");
        }
    }
    printf("\n");

    printf("Source:");
    for (int i = 0;i < 6;i++){
        printf("%02x",macHeader->SourceMacAddress[i]);
        if(i < 5){
            printf(":");
        }
    }
    printf("\n");

    MacTypeflag = 0;
    printf("Type:");
    for (int i = 0;i < 2;i++){
        printf("%02x",macHeader->MacType[i]);
        MacTypeflag <<= 8;
        MacTypeflag += 48 + macHeader->MacType[i] -'0';
    }
//    std::cout<<type<<std::endl;

    std::cout<<"("<<map_type[MacTypeflag]<<")"<<std::endl;
//    std::cout<<type_number<<std::endl;

}