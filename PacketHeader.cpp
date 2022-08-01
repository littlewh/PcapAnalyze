//
// Created by admin on 2022/7/27.
//

#include "PacketHeader.h"
#include <iostream>
#include <cstdint>

bool PacketHeader::GetPacketHeader(char *url,uint64_t offset) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("��ȡPacketHeaderʱ���ļ�ʧ��");
        return false;
    }
    else {
        fseek(fp,offset,SEEK_SET);
        if(fread(packetHeader,16,1,fp) != 1){
            printf("End of File!\n");
            fclose(fp);
            return false;
        }

        fclose(fp);
        return true;
    }

}

long long PacketHeader::AnalyzePacketHeader(bool pcapFlag) {
    long long TimestampHigh = 0;
    long long TimestampLow = 0;
    long long CapLen = 0;
    long long Len = 0;

    printf("TimestampHigh:");
    for(int i = 0;i < 4;i++){
        printf("%02x",packetHeader->char_timestamp_high[i]);
    }
    printf("\n");

    printf("TimestampLow:");
    for(int i = 0;i < 4;i++){
        printf("%02x",packetHeader->char_timestamp_low[i]);
    }
    printf("\n");

    printf("Caplen:");
    for(int i = 0;i < 4;i++){
        printf("%02x",packetHeader->char_caplen[i]);
    }
    printf("\n");

    printf("Len:");
    for(int i = 0;i < 4;i++){
        printf("%02x",packetHeader->char_len[i]);
    }
    printf("\n");

    if (pcapFlag == true){//С��
        for (int i = 3;i >= 0;i--){
            TimestampHigh <<= 8;
            TimestampHigh += 48+packetHeader->char_timestamp_high[i]-'0';

            TimestampLow <<= 8;
            TimestampLow += 48+packetHeader->char_timestamp_low[i]-'0';

            CapLen <<= 8;
            CapLen += 48+packetHeader->char_caplen[i]-'0';

            Len <<= 8;
            Len += 48+packetHeader->char_len[i]-'0';
        }
    }
    else {//���
        for (int i = 0;i <= 3;i++){
            TimestampHigh <<= 8;
            TimestampHigh += 48+packetHeader->char_timestamp_high[i]-'0';

            TimestampLow <<= 8;
            TimestampLow += 48+packetHeader->char_timestamp_low[i]-'0';

            CapLen <<= 8;
            CapLen += 48+packetHeader->char_caplen[i]-'0';

            Len <<= 8;
            Len += 48+packetHeader->char_len[i]-'0';
        }
    }

    std::cout<<"ʱ���:"<<TimestampHigh<<":"<<TimestampLow<<std::endl;
    std::cout<<"����������:"<<CapLen<<std::endl;
    std::cout<<"�������ݳ���:"<<Len<<std::endl;

    return CapLen;
}