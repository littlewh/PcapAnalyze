//
// Created by admin on 2022/8/1.
//

#include <cstdio>
#include "UDPHeader.h"

/*
 * 获取udp包头
 */

bool UDPHeader::GetUDPHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    return utilities.inputHeader(url,offset,used_offset,8,udpHeader);
}

/*
 * 分析udp包头
 */
void UDPHeader::AnalyzeUDPHeader(uint64_t &payload) {
    printf("Source Port:");
    source_port = utilities.DisplayArray(2,udpHeader->SourcePort);
    printf("(%d)",source_port);
    printf("\n");

    printf("Destination Port:");
    destination_port = utilities.DisplayArray(2,udpHeader->DestinationPort);
    printf("(%d)",destination_port);
    printf("\n");

    printf("Length:");
    int length = utilities.DisplayArray(2,udpHeader->Length);
    printf("(%d)",length);
    payload = length - 8;
    printf("\n");

    printf("Checksum:");
    utilities.DisplayArray(2,udpHeader->CheckSum);
    printf("\n");
}