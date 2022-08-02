//
// Created by admin on 2022/8/2.
//

#include "DNSHeader.h"

/*
 * ��ȡDNS�ײ�
 */
bool DNSHeader::GetDNSHeader(char *url, uint64_t offset, uint64_t &used_offset) {
    return utilities.inputHeader(url,offset,used_offset,12,dnsHeader);
}

/*
 * ����DNS�ײ�
 */

void DNSHeader::AnalyzeDNSHeader(uint64_t &ipTotalLen) {
    ipTotalLen -= 12;

    printf("TransactionID:");
    utilities.DisplayArray(2,dnsHeader->TransactionID);
    printf("\n");

    printf("Flags:");
    utilities.DisplayArray(2,dnsHeader->Flags);
    dns_Type = dnsHeader->Flags[0]/128;
    if(dns_Type == 0){
        printf("\t��ѯ");
    }
    else{
        printf("\t��Ӧ");
    }
    printf("\n");

    printf("Questions:");
    utilities.DisplayArray(2,dnsHeader->Questions);
    printf("\n");

    printf("AnswerRRs:");
    utilities.DisplayArray(2,dnsHeader->AnswerRRs);
    printf("\n");

    printf("AuthorityRRs:");
    utilities.DisplayArray(2,dnsHeader->AuthorityRRs);
    printf("\n");

    printf("AdditionalRRs:");
    utilities.DisplayArray(2,dnsHeader->AdditionalRRs);
    printf("\n");
}