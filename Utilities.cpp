//
// Created by admin on 2022/8/1.
//

#include "Utilities.h"
#include <cstdio>
#include <cstring>
#include <iostream>

/*
 * 数组的遍历分析显示
 */
long long Utilities::DisplayArray(int cnt, uint8_t *addr) {
    long long ans = 0;

    for(int i = 0;i < cnt;i++){
        ans <<= 8;
        ans += 48+addr[i]-'0';
        printf("%02x",addr[i]);
    }

    return ans;
}
/*
 * 单个元素的分析显示
 */
int Utilities::DisplayElement(uint8_t element) {
    printf("%02x",element);
    return 48+element-'0';
}

/*
 * 退格
 */
void Utilities::BackSpace(int number) {
    for(int i = 1;i <= number;i++){
        printf("\b");
    }
}

/*
 * KMP
 * 查找子串
 */
uint64_t Utilities::Find_KMP(char *data_string, char *target_string) {
    uint64_t data_len = strlen(data_string);
    uint64_t tar_len = strlen(target_string);
    uint64_t next[data_len];
    uint64_t t1 = 0;
    uint64_t t2 = -1;
    next[0] = -1;
    while(t1 < tar_len){
        if(t2 == -1 || target_string[t1] == target_string[t2]){
            t1++;
            t2++;
            next[t1] = t2;
        }

        else{
            t2=next[t2];//失配
        }
    }
    t1=0;
    t2=0;
    while(t1 < data_len){//临界值
        if(t2 == -1 || data_string[t1] == target_string[t2]){//匹配成功，继续
            t1++;
            t2++;
        }

        else{
            t2 = next[t2]; //失配
        }
        if(t2 == tar_len){
            return t1-tar_len+1;
        }
    }
}

/*
 * 抽象出的输入函数
 */
bool Utilities::inputHeader(char *url, uint64_t offset, uint64_t &used_offset, uint64_t len, void *object) {
    FILE *fp = fopen(url,"rb");
    if (fp == NULL){
        printf("打开文件失败");
        return false;
    }
    else {
        offset += used_offset;//加上偏移
        fseek(fp,offset,SEEK_SET);
        fread(object,len,1,fp);
        used_offset += len;
        fclose(fp);
        return true;
    }
}

/*
 * 在报文中分理出字段
 */
std::string Utilities::findItemInData(std::string item_start,std::string item_end,std::string data) {
    std::string::size_type pos_start = data.find(item_start);
    if(pos_start != data.npos){
        std::string::size_type pos_end = data.find(item_end,pos_start+1);
        std::string ss = data.substr(pos_start,pos_end-pos_start);
        std::cout<<ss<<std::endl;
        return ss;
    }

    return "";
}

/*
 * 分析dns响应报文时的重复工作
 */

uint64_t Utilities::DNSAnswerHeader(uint8_t data[],uint64_t &length, uint64_t &payload,std::map<int,std::string > &map_Class) {
    printf("Class:");
    uint64_t number = 0;
    for(int i = length;i < length+2;i++){
        number <<= 8;
        number += 48+(uint8_t)data[i]-'0';
        printf("%x",(uint8_t)data[i]);
    }
    std::cout<<"("<<map_Class[number]<<")"<<std::endl;
    length += 2;
    payload -= 2;

    printf("Time to live:");
    number = 0;
    for(int i = length;i < length+4;i++){
        number <<= 8;
        number += 48+(uint8_t)data[i]-'0';
        printf("%x",(uint8_t)data[i]);
    }
    std::cout<<"("<<number<<")"<<std::endl;
    length += 4;
    payload -= 4;

    printf("Data Length:");
    uint64_t data_length = 0;
    for(int i = length;i < length+2;i++){
        data_length <<= 8;
        data_length += 48+(uint8_t)data[i]-'0';
        printf("%x",(uint8_t)data[i]);
    }
    std::cout<<"("<<data_length<<")"<<std::endl;
    length += 2;
    payload -= 2;

    return data_length;
}

/*
 * 为确定四元组的key进行哈希,
 * 源ip|目的ip，源端口|目的端口
 */

uint64_t Utilities::HTTPHashFunction(uint32_t source_ip, uint32_t destination_ip, uint32_t source_port,uint32_t destination_port) {
    uint64_t ip = (source_ip  + destination_ip) % 122777;
    uint64_t port = (source_port + destination_port) % 690163;

    return (ip+port)%218357;
}