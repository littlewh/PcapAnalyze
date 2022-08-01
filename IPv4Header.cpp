//
// Created by admin on 2022/7/28.
//

#include "IPv4Header.h"

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
    int total_length = 0;
    for(int i = 0;i < 2;i++){
        total_length <<= 8;
        total_length += 48+ipv4Header->TotalLength[i]-'0';
        printf("%02x",ipv4Header->TotalLength[i]);
    }
    printf("(%d)",total_length);
    printf("\n");

    printf("Identification:");
    int identification = 0;
    for(int i = 0;i < 2;i++){
        identification <<= 8;
        identification += 48+ipv4Header->Identification[i]-'0';
        printf("%02x",ipv4Header->Identification[i]);
    }
    printf("(%d)",identification);
    printf("\n");

    printf("Flags and FragementOffset:");
    for(int i = 0;i < 2;i++){
        printf("%02x",ipv4Header->FlagsAndFragementOffset[i]);
    }
    printf("\n");

    printf("Time to Live:");
    printf("%02x (%d)",ipv4Header->TimeToLive,48+ipv4Header->TimeToLive-'0');
    printf("\n");

    printf("Protocol:");
    printf("%02x ",ipv4Header->Protocol);
    ipProtocolType = ipv4Header->Protocol;
    std::cout<<"("<<map_protocol[ipProtocolType]<<")";
    printf("\n");

    printf("Header Checksum:");
    for(int i = 0;i < 2;i++){
        printf("%02x",ipv4Header->HeaderChecksum[i]);
    }
    printf("\n");

    printf("Source Address:");
    for(int i = 0;i < 4;i++){
        printf("%02x",ipv4Header->SourceAddress[i]);
    }
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
    for(int i = 0;i < 4;i++){
        printf("%02x",ipv4Header->DestinationAddress[i]);
    }
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