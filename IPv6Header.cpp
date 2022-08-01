//
// Created by admin on 2022/7/29.
//

#include "IPv6Header.h"
#include "Utilities.h"

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
    Utilities utilities;

    printf("Version:");
    printf("%01x",ipv6Header->VersionAndTrafiicHigh/16);
    printf("\n");

    printf("Traffic Class:");
    printf("%01x%01x",ipv6Header->VersionAndTrafiicHigh%16,ipv6Header->TrafiicLowAndFlowHigh/16);
    printf("\n");

    printf("FlowLabel:");
    printf("%01x",ipv6Header->TrafiicLowAndFlowHigh%16);
    utilities.DisplayArray(2,ipv6Header->FlowLable);
    printf("\n");

    printf("PayLoad Length:");
    long long payload_length = utilities.DisplayArray(2,ipv6Header->PayloadLength);
    printf("(%lld)",payload_length);
    printf("\n");

    printf("Next Header:");
    nextHeader = utilities.DisplayElement(ipv6Header->NextHeader);
    std::cout<<"("<<map_nextheader[nextHeader]<<")";
    printf("\n");

    printf("Hop Limit:");
    printf("(%d)",utilities.DisplayElement(ipv6Header->HopLimit));
    printf("\n");

    printf("Source Address:");
    utilities.DisplayArray(16,ipv6Header->SourceAddress);
    printf("\n");

    printf("Destination Address:");
    utilities.DisplayArray(16,ipv6Header->DestinationAddress);
    printf("\n");

}