//
// Created by admin on 2022/7/29.
//

#include "IPv6Header.h"

bool IPv6Header::GetIPHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取IPHeader时打开文件失败");
        return false;
    }
    else {
        offset += used_offset;//加上Mac偏移
        fseek(fp,offset,SEEK_SET);
        fread(ipv6Header,40,1,fp);
        used_offset += 40;
        fclose(fp);
        return true;
    }
}

void IPv6Header::AnalyzeIPHeader() {
    printf("Version:");
    printf("%01x",ipv6Header->VersionAndTrafiicHigh/16);
    printf("\n");

    printf("Traffic Class:");
    printf("%01x%01x",ipv6Header->VersionAndTrafiicHigh%16,ipv6Header->TrafiicLowAndFlowHigh/16);
    printf("\n");

    printf("FlowLabel:");
    printf("%01x",ipv6Header->TrafiicLowAndFlowHigh%16);
    for (int i = 0;i < 2;i++){
        printf("%02x",ipv6Header->FlowLable[i]);
    }
    printf("\n");

    printf("PayLoad Length:");
    int payload_length = 0;
    for (int i = 0;i < 2;i++){
        payload_length <<= 8;
        payload_length += 48+ipv6Header->PayloadLength[i]-'0';
        printf("%02x",ipv6Header->PayloadLength[i]);
    }
    printf("(%d)",payload_length);
    printf("\n");

    printf("Next Header:");
    nextHeader = 48+ipv6Header->NextHeader-'0';
    printf("%02x",ipv6Header->NextHeader);
    std::cout<<"("<<map_nextheader[nextHeader]<<")";
    printf("\n");

    printf("Hop Limit:");
    printf("%02x(%d)",ipv6Header->HopLimit,48+ipv6Header->HopLimit-'0');
    printf("\n");

    printf("Source Address:");
    for (int i = 0;i < 4;i++){
        printf("%02x",ipv6Header->SourceAddress[i]);
    }
    printf("\n");

    printf("Destination Address:");
    for (int i = 0;i < 4;i++){
        printf("%02x",ipv6Header->DestinationAddress[i]);
    }
    printf("\n");

}