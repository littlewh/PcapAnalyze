//
// Created by admin on 2022/8/2.
//

#include <iostream>
#include "DNSHeader.h"

/*
 * 获取DNS首部
 */
bool DNSHeader::GetDNSHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    return utilities.inputHeader(url,offset,used_offset,12,dnsHeader);
}

/*
 * 分析DNS首部
 */

void DNSHeader::AnalyzeDNSHeader(uint64_t &payloadLen) {
    payloadLen -= 12;

    printf("TransactionID:");
    TransactionID = utilities.DisplayArray(2,dnsHeader->TransactionID);

    printf("\n");

    printf("Flags:");
    utilities.DisplayArray(2,dnsHeader->Flags);
    uint32_t response = (dnsHeader->Flags[0]>>7);
    uint32_t opcode = (dnsHeader->Flags[0]>>3) - ((dnsHeader->Flags[0]>>7)<<4);
    uint32_t aa = ((dnsHeader->Flags[0]%8 -dnsHeader->Flags[0]%4)>>2);
    uint32_t truncated = ((dnsHeader->Flags[0]%4 - dnsHeader->Flags[0]%2)>>1);
    uint32_t recursion = dnsHeader->Flags[0]%2;
    uint32_t ra = (dnsHeader->Flags[1]>>7);
    uint32_t z = ((dnsHeader->Flags[1]>>6) - ((dnsHeader->Flags[0]>>7)<<1));
    uint32_t rcode = (dnsHeader->Flags[1]%16);
    dns_Type = 48 + response - '0';
    printf("Response:%d",48 + response - '0');
    std::cout<<"\t:"<<map_qr[48 + response - '0']<<std::endl;

    printf("Opcode:%d",48 + opcode - '0');
    std::cout<<"\t:"<<map_code[48 + opcode - '0']<<std::endl;

    if(dns_Type == 1){
        printf("Authoritative:%d",48 + aa - '0');
        std::cout<<"\t:"<<map_aa[48 + aa - '0']<<std::endl;
    }

    printf("Truncated:%d",48 + truncated - '0');
    std::cout<<"\t:"<<map_tc[48 + truncated - '0']<<std::endl;

    printf("Recursion:%d",48 + recursion - '0');
    std::cout<<"\t:"<<map_rd[48 + recursion  - '0']<<std::endl;

    if(dns_Type == 1){
        printf("Recursion Available:%d",48 + ra - '0');
        std::cout<<"\t:"<<map_ra[48 + ra - '0']<<std::endl;

        printf("Reply Code:%d",48+rcode-'0');
        std::cout<<"\t:"<<map_rcode[48+rcode-'0']<<std::endl;
    }

    printf("Z:%d\n",48 + z - '0');


    printf("Questions:");
    uint32_t question = utilities.DisplayArray(2,dnsHeader->Questions);
    std::cout<<"("<<question<<")";
    printf("\n");

    printf("AnswerRRs:");
    uint32_t ans_rrs = utilities.DisplayArray(2,dnsHeader->AnswerRRs);
    std::cout<<"("<<ans_rrs<<")";
    printf("\n");

    printf("AuthorityRRs:");
    uint32_t au_rrs = utilities.DisplayArray(2,dnsHeader->AuthorityRRs);
    std::cout<<"("<<au_rrs<<")";
    printf("\n");

    printf("AdditionalRRs:");
    uint32_t add_rrs = utilities.DisplayArray(2,dnsHeader->AdditionalRRs);
    std::cout<<"("<<add_rrs<<")";
    printf("\n");
}