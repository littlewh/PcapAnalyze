//
// Created by admin on 2022/7/29.
//

#include <cstdio>
#include <iostream>
#include "ICMPHeader.h"
#include "Utilities.h"

/*
 * 获取icmp报文头
 */
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
/*
 * 分析icmp报文头
 */
void ICMPHeader::AnalyzeICMPHeader() {
    Utilities utilities;

    printf("Type:");
    int icmp_type = utilities.DisplayElement(icmpHeader->Type);
    std::cout<<"("<<map_type[icmp_type]<<")";
    printf("\n");

    printf("Code:");
    int icmp_code = utilities.DisplayElement(icmpHeader->Code);
    std::cout<<"("<<map_code[icmp_code]<<")";
    printf("\n");

    printf("CheckSum:");
    utilities.DisplayArray(2,icmpHeader->CheckSum);
    printf("\n");

    int icmp_identifier = utilities.DisplayArray(2,icmpHeader->Identifier);
    utilities.BackSpace(4);
    int icmp_sequence_number = utilities.DisplayArray(2,icmpHeader->SequenceNumber);
    utilities.BackSpace(4);
    if(icmp_identifier == 0 && icmp_sequence_number == 0){//差错报文
        errorFlag = true;
        printf("Unused:");
        utilities.DisplayArray(2,icmpHeader->Identifier);
        utilities.DisplayArray(2,icmpHeader->SequenceNumber);
        printf("\n");
    }
    else{
        printf("Identifier:");
        utilities.DisplayArray(2,icmpHeader->Identifier);
        printf("\n");
        printf("Sequence Number:");
        utilities.DisplayArray(2,icmpHeader->SequenceNumber);
        printf("\n");
    }
}