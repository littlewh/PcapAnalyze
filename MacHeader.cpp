//
// Created by admin on 2022/7/28.
//

#include <iostream>
#include "MacHeader.h"
/*
 * 获取Mac包头
 */
bool::MacHeader::GetMacHeader(char *url,uint64_t offset,uint64_t &used_offset){
    return utilities.inputHeader(url,offset,used_offset,14,macHeader);
}
/*
 * 分析Mac包头
 */
void::MacHeader::AnalyzeMacHeader(){


    printf("Destination:");
    for (int i = 0;i < 6;i++){
        printf("%02x",macHeader->DesTinationMacAddress[i]);
        if(i < 5){
            printf(":");
        }
    }
    printf("\n");

    printf("Source:");
    for (int i = 0;i < 6;i++){
        printf("%02x",macHeader->SourceMacAddress[i]);
        if(i < 5){
            printf(":");
        }
    }
    printf("\n");


    printf("Type:");
    MacTypeflag = utilities.DisplayArray(2,macHeader->MacType);
//    std::cout<<type<<std::endl;

    std::cout<<"("<<map_type[MacTypeflag]<<")"<<std::endl;
//    std::cout<<type_number<<std::endl;

}