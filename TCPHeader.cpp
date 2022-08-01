//
// Created by admin on 2022/7/28.
//

#include "TCPHeader.h"
bool TCPHeader::GetTCPHeader(char *url,uint64_t offset,uint64_t &used_offset){
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取IPHeader时打开文件失败");
        return false;
    }
    else {
        offset += used_offset;//加上Mac偏移 和 IP偏移
        fseek(fp,offset,SEEK_SET);
        fread(tcpHeader,20,1,fp);
        used_offset += 20;
        fclose(fp);
        return true;
    }
}

void TCPHeader::AnalyzeTCPHeader() {
    printf("Source Port:");
    int source_port = 0;
    for (int i = 0;i < 2;i++){
        source_port <<= 8;
        source_port += 48+tcpHeader->SourcePort[i]-'0';
        printf("%02x",tcpHeader->SourcePort[i]);
    }
    printf("(%d)",source_port);
    printf("\n");

    printf("Destination Port:");
    int destination_port = 0;
    for (int i = 0;i < 2;i++){
        destination_port <<= 8;
        destination_port += 48+tcpHeader->DestinationPort[i]-'0';
        printf("%02x",tcpHeader->DestinationPort[i]);
    }
    printf("(%d)",destination_port);
    printf("\n");

    printf("Sequence Number:");
    unsigned int sequence_number = 0;
    for (int i = 0;i < 4;i++){
        sequence_number <<= 8;
        sequence_number += 48+tcpHeader->SequenceNumber[i]-'0';
        printf("%02x",tcpHeader->SequenceNumber[i]);
    }
    printf("(%u)",sequence_number);
    printf("\n");

    printf("Acknowledgment Number:");
    unsigned int acknowledgment_number = 0;
    for (int i = 0;i < 4;i++){
        acknowledgment_number <<= 8;
        acknowledgment_number += 48+tcpHeader->AcknowledgmentNumber[i]-'0';
        printf("%02x",tcpHeader->AcknowledgmentNumber[i]);
    }
    printf("(%u)",acknowledgment_number);
    printf("\n");

    printf("Header Length:");
    printf("%01x",tcpHeader->OffsetReserveFlag[0]/16);
    printf("(%d bytes)",4*(48+tcpHeader->OffsetReserveFlag[0]/16-'0'));
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
    int window = 0;
    for (int i = 0;i < 2;i++){
        window <<= 8;
        window += 48+tcpHeader->Window[i]-'0';
        printf("%02x",tcpHeader->Window[i]);
    }
    printf("(%d)",window);
    printf("\n");

    printf("Checksum:");
    for (int i = 0;i < 2;i++){
        printf("%02x",tcpHeader->CheckSum[i]);
    }
    printf("\n");

    printf("Urgent Pointer:");
    for (int i = 0;i < 2;i++){
        printf("%02x",tcpHeader->UrgentPointer[i]);
    }
    printf("\n");
}