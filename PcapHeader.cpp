//
// Created by admin on 2022/7/27.
//

#include <iostream>
#include <fstream>
#include <cstdio>
#include "PcapHeader.h"

bool PcapHeader::GetPcapHeader(char *url,uint64_t offset) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("获取PcapHeader时打开文件失败");
        return false;
    }
    else {
        fseek(fp,offset,SEEK_SET);
        fread(pcapHeader,24,1,fp);
        offset += 24;
        fclose(fp);
        return true;
    }
}

bool PcapHeader::AnalyzePcapHeader() {
    long long magic = 0;
    long long SnapLenNumber = 0;
    long MajorNumber = 0;
    long MinorNumber = 0;
    LinkTypeFlag = 0;

    printf("Magic:");
    for(int i = 0;i < 4;i++){
        magic <<= 8;
        magic += 48+pcapHeader->char_magic[i]-'0';
        printf("%02x",pcapHeader->char_magic[i]);
    }
    printf("\n");

    printf("Major:");
    for(int i = 0;i < 2;i++){
        printf("%02x",pcapHeader->char_major[i]);
    }
    printf("\n");

    printf("Minor:");
    for(int i = 0;i < 2;i++){
        printf("%02x",pcapHeader->char_minor[i]);
    }
    printf("\n");

    printf("ThisZone:");
    for(int i = 0;i < 4;i++){
        printf("%02x",pcapHeader->char_thiszone[i]);
    }
    printf("\n");

    printf("SigFigs:");
    for(int i = 0;i < 4;i++){
        printf("%02x",pcapHeader->char_sigfigs[i]);
    }
    printf("\n");

    printf("SnapLen:");
    for(int i = 0;i < 4;i++){
        printf("%02x",pcapHeader->char_snap_len[i]);
    }
    printf("\n");

    printf("LinkType:");
    for(int i = 0;i < 4;i++){
        printf("%02x",pcapHeader->char_linktype[i]);
    }
    printf("\n");

    if (magic == 3569595041){
        std::cout<<"小端模式"<<std::endl;

        for (int i = 3;i >= 0;i--){
//        printf("%x ",snap_len[i]);
//        std::cout<<48+snap_len[i]-'0'<<std::endl;//十进制的每位数
            SnapLenNumber <<= 8;
            SnapLenNumber += 48+pcapHeader->char_snap_len[i]-'0';
            if(i < 2){
                MajorNumber <<= 8;
                MajorNumber += 48+pcapHeader->char_major[i]-'0';

                MinorNumber <<= 8;
                MinorNumber += 48+pcapHeader->char_minor[i]-'0';
            }

            LinkTypeFlag <<= 8;
            LinkTypeFlag += 48+pcapHeader->char_linktype[i]-'0';
        }

    }
    else {
        std::cout<<"大端模式"<<std::endl;
        for (int i = 0;i <= 3;i++){
//            printf("%x ",snap_len[i]);
//        std::cout<<48+snap_len[i]-'0'<<std::endl;//十进制的每位数
            SnapLenNumber <<= 8;
            SnapLenNumber += 48+pcapHeader->char_snap_len[i]-'0';
            if(i < 2){
                MajorNumber <<= 8;
                MajorNumber += 48+pcapHeader->char_major[i]-'0';

                MinorNumber <<= 8;
                MinorNumber += 48+pcapHeader->char_minor[i]-'0';
            }

            LinkTypeFlag <<= 8;
            LinkTypeFlag += 48+pcapHeader->char_linktype[i]-'0';
        }
    }
    std::cout<<"最大存储长度:"<<SnapLenNumber<<std::endl;
    std::cout<<"主版本号:"<<MajorNumber<<std::endl;
    std::cout<<"次版本号:"<<MinorNumber<<std::endl;
    std::cout<<"链路类型:"<<map_linktype[LinkTypeFlag]<<std::endl;

    if (magic == 3569595041){
        return true;
    }
    else{
        return false;
    }
}