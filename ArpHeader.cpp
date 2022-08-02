//
// Created by admin on 2022/7/29.
//

#include "ArpHeader.h"

/*
 * 获取Arp包头
 */
bool ArpHeader::GetArpHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    return utilities.inputHeader(url,offset,used_offset,28,arpHeader);
}

/*
 * 分析Arp包头
 */

void ArpHeader::AnalyzeArpHeader() {

    printf("Hardware Type:");
    utilities.DisplayArray(2,arpHeader->HardwareType);
    printf("\n");

    printf("Protocol Type:");
    protocol_type = utilities.DisplayArray(2,arpHeader->ProtocolType);
    std::cout<<"("<<map_protocol[protocol_type]<<")";
    printf("\n");

    printf("Hardware Size:");
    printf("%(%d)",utilities.DisplayElement(arpHeader->HardwareSize));
    printf("\n");

    printf("Protocol Size:");
    printf("%(%d)",utilities.DisplayElement(arpHeader->ProtocolSize));
    printf("\n");

    printf("OpCode:");
    int op_code = utilities.DisplayArray(2,arpHeader->OpCode);
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
    utilities.DisplayArray(4,arpHeader->SenderIPAddress);
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
    utilities.DisplayArray(4,arpHeader->TargetIPAddress);
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