//
// Created by admin on 2022/7/28.
//

#include "IPv4Header.h"
#include "Utilities.h"

bool IPv4Header::GetIPHeader(char *url,uint64_t offset,uint64_t &used_offset){
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取IPHeader时打开文件失败");
        return false;
    }
    else {
        offset += used_offset;//加上Mac偏移
        fseek(fp,offset,SEEK_SET);
        fread(ipv4Header,20,1,fp);
        used_offset += 20;
        fclose(fp);
        return true;
    }
}

void::IPv4Header::AnalyzeIPHeader(){
    Utilities utilities;

    printf("Version:");
    printf("%01x",ipv4Header->VersionAndIHL/16);
    printf("\n");

    printf("IHL:");
    printf("%01x",ipv4Header->VersionAndIHL%16);
    printf("\n");

    printf("Type of Service:");
    printf("%02x",ipv4Header->TypeOfService);
    printf("\n");

    printf("Total Length:");
    long long total_length = utilities.DisplayArray(2,ipv4Header->TotalLength);
    printf("(%lld)",total_length);
    printf("\n");

    printf("Identification:");
    long long identification = utilities.DisplayArray(2,ipv4Header->Identification);
    printf("(%lld)",identification);
    printf("\n");

    printf("Flags and FragementOffset:");
    utilities.DisplayArray(2,ipv4Header->FlagsAndFragementOffset);
    printf("\n");

    printf("Time to Live:");
    printf("(%d)",utilities.DisplayElement(ipv4Header->TimeToLive));
    printf("\n");

    printf("Protocol:");
    ipProtocolType = utilities.DisplayElement(ipv4Header->Protocol);
    std::cout<<"("<<map_protocol[ipProtocolType]<<")";
    printf("\n");

    printf("Header Checksum:");
    utilities.DisplayArray(2,ipv4Header->HeaderChecksum);
    printf("\n");

    printf("Source Address:");
    utilities.DisplayArray(4,ipv4Header->SourceAddress);
    printf("(");//转为十进制的ip形式
    for(int i = 0;i < 4;i++){
        printf("%d",48+ipv4Header->SourceAddress[i]-'0');
        if(i < 3){
            printf(".");
        }
    }
    printf(")");
    printf("\n");

    printf("Destination Address:");
    utilities.DisplayArray(4,ipv4Header->DestinationAddress);
    printf("(");//转为十进制的ip形式
    for(int i = 0;i < 4;i++){
        printf("%d",48+ipv4Header->DestinationAddress[i]-'0');
        if(i < 3){
            printf(".");
        }
    }
    printf(")");
    printf("\n");

}