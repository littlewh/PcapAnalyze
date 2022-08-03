//
// Created by admin on 2022/7/28.
//

#include "IPv4Header.h"

/*
 * 获取IPv4包头
 */
bool IPv4Header::GetIPHeader(char *url,uint64_t offset,uint64_t &used_offset){
    return utilities.inputHeader(url,offset,used_offset,20,ipv4Header);
}
/*
 * 分析IPv4包头
 */
void::IPv4Header::AnalyzeIPHeader(uint64_t &used_offset,uint64_t &ipTotalLen){
    printf("Version:");
    printf("%01x",ipv4Header->VersionAndIHL/16);
    printf("\n");

    printf("HeaderLength:");
    printf("%01x",ipv4Header->VersionAndIHL%16);
    int32_t header_len = 4*(48+ipv4Header->VersionAndIHL%16-'0');
    printf("(%d bytes)",header_len);
    if(header_len > 20){
        used_offset += header_len - 20;
    }
    printf("\n");

    printf("Type of Service:");
    printf("%02x",ipv4Header->TypeOfService);
    printf("\n");

    printf("Total Length:");
    long long total_length = utilities.DisplayArray(2,ipv4Header->TotalLength);
    ipTotalLen = total_length-header_len;//求出负载长度
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
    source_ip = utilities.DisplayArray(4,ipv4Header->SourceAddress);
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
    destination_ip = utilities.DisplayArray(4,ipv4Header->DestinationAddress);
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