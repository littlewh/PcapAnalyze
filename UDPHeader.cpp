//
// Created by admin on 2022/8/1.
//

#include <cstdio>
#include "UDPHeader.h"
#include "Utilities.h"

/*
 * 获取udp包头
 */

bool UDPHeader::GetTCPHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取UDPHeader时打开文件失败");
        return false;
    }
    else {
        offset += used_offset;//加上Mac偏移 和 IP偏移
        fseek(fp,offset,SEEK_SET);
        fread(udpHeader,8,1,fp);
        used_offset += 8;
        fclose(fp);
        return true;
    }
}

/*
 * 分析udp包头
 */
void UDPHeader::AnalyzeTCPHeader() {
    printf("Source Port:");
    Utilities utilities;
    int source_port = utilities.DisplayArray(2,udpHeader->SourcePort);
    printf("(%d)",source_port);
    printf("\n");

    printf("Destination Port:");
    destination_port = utilities.DisplayArray(2,udpHeader->DestinationPort);
    printf("(%d)",destination_port);
    printf("\n");

    printf("Length:");
    int length = utilities.DisplayArray(2,udpHeader->Length);
    printf("(%d)",length);
    printf("\n");

    printf("Checksum:");
    utilities.DisplayArray(2,udpHeader->CheckSum);
    printf("\n");
}