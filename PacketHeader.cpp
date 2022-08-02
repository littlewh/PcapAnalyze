//
// Created by admin on 2022/7/27.
//

#include "PacketHeader.h"
#include <iostream>
#include <cstdint>
#include "Utilities.h"
/*
 * 获取Packet包头
 */
bool PacketHeader::GetPacketHeader(char *url,uint64_t offset) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取PacketHeader时打开文件失败");
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
/*
 * 分析Packet包头
 */
long long PacketHeader::AnalyzePacketHeader(bool pcapFlag) {
    long long TimestampHigh = 0;
    long long TimestampLow = 0;
    long long CapLen = 0;
    long long Len = 0;
    Utilities utilities;

    printf("TimestampHigh:");
    utilities.DisplayArray(4,packetHeader->char_timestamp_high);
    printf("\n");

    printf("TimestampLow:");
    utilities.DisplayArray(4,packetHeader->char_timestamp_low);
    printf("\n");

    printf("Caplen:");
    utilities.DisplayArray(4,packetHeader->char_caplen);
    printf("\n");

    printf("Len:");
    utilities.DisplayArray(4,packetHeader->char_len);
    printf("\n");

    if (pcapFlag == true){//小端
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
    else {//大端
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

    std::cout<<"时间戳:"<<TimestampHigh<<":"<<TimestampLow<<std::endl;
    std::cout<<"数据区长度:"<<CapLen<<std::endl;
    std::cout<<"离线数据长度:"<<Len<<std::endl;

    return CapLen;
}