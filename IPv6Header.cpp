//
// Created by admin on 2022/7/29.
//

#include "IPv6Header.h"

/*
 * 获取IPv6包头
 */

bool IPv6Header::GetIPHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    return utilities.inputHeader(url,offset,used_offset,40,ipv6Header);
}

/*
 * 分析IPv6包头
 */
void IPv6Header::AnalyzeIPHeader(uint64_t &ipTotalLen) {
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
    ipTotalLen = payload_length;
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