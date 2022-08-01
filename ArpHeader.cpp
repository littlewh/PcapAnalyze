//
// Created by admin on 2022/7/29.
//

#include "ArpHeader.h"
bool ArpHeader::GetArpHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取ArpHeader时打开文件失败");
        return false;
    }
    else {
        offset += used_offset;//加上Mac偏移
        fseek(fp,offset,SEEK_SET);
        fread(arpHeader,28,1,fp);
        used_offset += 28;
        fclose(fp);
        return true;
    }
}

void ArpHeader::AnalyzeArpHeader() {
    printf("Hardware Type:");
    for(int i = 0;i < 2;i++){
        printf("%02x",arpHeader->HardwareType[i]);
    }
    printf("\n");

    printf("Protocol Type:");
    protocol_type = 0;
    for(int i = 0;i < 2;i++){
        protocol_type <<= 8;
        protocol_type += 48+arpHeader->ProtocolType[i]-'0';
        printf("%02x",arpHeader->ProtocolType[i]);
    }
    std::cout<<"("<<map_protocol[protocol_type]<<")";
    printf("\n");

    printf("Hardware Size:");
    printf("%02x(%d)",arpHeader->HardwareSize,48+arpHeader->HardwareSize-'0');
    printf("\n");

    printf("Protocol Size:");
    printf("%02x(%d)",arpHeader->ProtocolSize,48+arpHeader->ProtocolSize-'0');
    printf("\n");

    printf("OpCode:");
    int op_code = 0;
    for(int i = 0;i < 2;i++){
        op_code <<= 8;
        op_code += 48+arpHeader->OpCode[i]-'0';
        printf("%02x",arpHeader->OpCode[i]);
    }
    std::cout<<"("<<map_opcode[op_code]<<")";
    printf("\n");

    printf("SenderMacAddress:");
    for(int i = 0;i < 6;i++){
        printf("%02x",arpHeader->SenderMacAddress[i]);
        if(i < 5){
            printf(":");
        }
    }
    printf("\n");

    printf("SenderIPAddress:");
    for(int i = 0;i < 4;i++){
        printf("%02x",arpHeader->SenderIPAddress[i]);
    }
    printf("(");
    for(int i = 0;i < 4;i++){
        printf("%d",48+arpHeader->SenderIPAddress[i]-'0');
        if(i < 3){
            printf(".");
        }
    }
    printf(")");
    printf("\n");

    printf("TargetMacAddress:");
    for(int i = 0;i < 6;i++){
        printf("%02x",arpHeader->TargetMacAddress[i]);
        if(i < 5){
            printf(":");
        }
    }
    printf("\n");

    printf("TargetIPAddress:");
    for(int i = 0;i < 4;i++){
        printf("%02x",arpHeader->TargetIPAddress[i]);
    }
    printf("(");
    for(int i = 0;i < 4;i++){
        printf("%d",48+arpHeader->TargetIPAddress[i]-'0');
        if(i < 3){
            printf(".");
        }
    }
    printf(")");
    printf("\n");
}