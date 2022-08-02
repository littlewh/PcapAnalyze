//
// Created by admin on 2022/7/28.
//

#include "TCPHeader.h"

/*
 * 获取TCP包头
 */
bool TCPHeader::GetTCPHeader(char *url,uint64_t offset,uint64_t &used_offset){
    return utilities.inputHeader(url,offset,used_offset,20,tcpHeader);
}

/*
 * 分析TCP包头
 */
void TCPHeader::AnalyzeTCPHeader(uint64_t &used_offset,uint64_t &payload) {
    printf("Source Port:");
    source_port = utilities.DisplayArray(2,tcpHeader->SourcePort);
    printf("(%d)",source_port);
    printf("\n");

    printf("Destination Port:");
    destination_port = utilities.DisplayArray(2,tcpHeader->DestinationPort);
    printf("(%d)",destination_port);
    printf("\n");

    printf("Sequence Number:");
    long long sequence_number = utilities.DisplayArray(4,tcpHeader->SequenceNumber);
    printf("(%lld)",sequence_number);
    printf("\n");

    printf("Acknowledgment Number:");
    long long acknowledgment_number = utilities.DisplayArray(4,tcpHeader->AcknowledgmentNumber);
    printf("(%lld)",acknowledgment_number);
    printf("\n");

    printf("Header Length:");
    printf("%01x",tcpHeader->OffsetReserveFlag[0]/16);
    int32_t header_len = 4*(48+tcpHeader->OffsetReserveFlag[0]/16-'0');
    printf("(%d bytes)",header_len);
    if(header_len > 20){
        used_offset += header_len - 20;
    }
    payload -= header_len;
    printf("\n");

    printf("Flags:");
    tcp_flags = 0;
    tcp_flags <<= 8;
    tcp_flags += 48+tcpHeader->OffsetReserveFlag[0]%16-'0';
    printf("%01x",tcpHeader->OffsetReserveFlag[0]%16);
    tcp_flags <<= 8;
    tcp_flags += tcpHeader->OffsetReserveFlag[1];
    printf("%02x",tcpHeader->OffsetReserveFlag[1]);
    printf("\n");
//    printf("%d\n",tcp_flags);

    printf("Window:");
    long long window = utilities.DisplayArray(2,tcpHeader->Window);;
    printf("(%lld)",window);
    printf("\n");

    printf("Checksum:");
    utilities.DisplayArray(2,tcpHeader->CheckSum);
    printf("\n");

    printf("Urgent Pointer:");
    utilities.DisplayArray(2,tcpHeader->UrgentPointer);
    printf("\n");
}