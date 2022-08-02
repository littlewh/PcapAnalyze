#include <iostream>
#include <fstream>
#include <string>
#include "PcapHeader.h"
#include "PacketHeader.h"
#include "MacHeader.h"
#include "IPv4Header.h"
#include "IPv6Header.h"
#include "TCPHeader.h"
#include "ArpHeader.h"
#include "ICMPHeader.h"
#include "UDPHeader.h"
#include "Data.h"
#include "DNSHeader.h"

class PcapFile{
public:
    PcapFile(){
//        std::string url = "";//��������Ŀ���ļ�·��
//        std::cin>>url;
        url = "E:\\TestProject\\PcapAnalyze\\2.pcap";
    }
    void inputFile(){
        inputPcapHeader();
        FILE *fp = fopen(url,"rb");//����rb������r�������ʮ���������ݣ�����0x1A���ᱻ���ϳ�EOF�����¶���
        if (fp == NULL){
            printf("���ļ�ʧ��");
            return ;
        }
        int cnt = 0;//��¼�ڼ�����
        offset = 24;//���� offsetָ�����pcap�ļ�ͷ

        while(fseek(fp,offset,SEEK_SET) == 0){

//            std::cout<<offset<<std::endl;
            bool endFlag = inputPackHeader();//�ļ�β
            if(!endFlag){
                break;
            }
            cnt ++;

            if(cnt == 48){
                break;
            }

            printf("\n**********��%d����**********\n",cnt);
            offset += 16;//���� offsetָ�����packet��ͷ

            uint64_t used_offset = 0;//��¼ƫ����

            if(pcapHeader.LinkTypeFlag == 1){//��̫��֡
                inputMacHeader(used_offset);
            }

            offset +=  CapLen;//��������ľͲ��������ã�ֻ��ֵ���ݼ���
            printf("***************************\n");
        }
        fclose(fp);

    }

private:
    PcapHeader pcapHeader;
    PacketHeader packetHeader;
    MacHeader macHeader;
    IPv4Header ipv4Header;
    IPv6Header ipv6Header;
    TCPHeader tcpHeader;
    ArpHeader arpHeader;
    ICMPHeader icmpHeader;
    UDPHeader udpHeader;
    HTTPRequestData httpRequestData;
    HTTPRespoundData httpRespoundData;
    DNSHeader dnsHeader;
    DNSQueryData dnsQueryData;
    DNSRespoundData dnsRespoundData;

    std::ifstream pcap_file;
    bool pcapFlag;//�жϴ�С��
    char *url;//�ļ�·��
    uint64_t offset;//��ǰƫ������Ϊ��fseek�Ķ�λʹ��
    uint64_t CapLen;
    /*
     * ���س���
     * Ϊ�˷�ֹ���ִ���mac֡β�����������ʹ��Caplen����payload�����븺�س��ȣ���ip���ĵ�length��ʼ��¼
     */
    uint64_t ipTotalLen;

    void inputPcapHeader();
    bool inputPackHeader();
    void inputMacHeader(uint64_t &used_offset);
    void inputIPv4Header(uint64_t &used_offset);
    void inputTCPHeader(uint64_t &used_offset);
    void inputIPv6Header(uint64_t &used_offset);
    void inputArpHeader(uint64_t &used_offset);
    void inputICMPHeader(uint64_t &used_offset);
    void inputUDPHeader(uint64_t &used_offset);
};

void PcapFile::inputPcapHeader() {
    offset = 0;
    std::cout<<"*****Pcap Header*****\n";
    pcapHeader.GetPcapHeader(url,offset);
    pcapFlag = pcapHeader.AnalyzePcapHeader();
}

bool PcapFile::inputPackHeader() {


    bool endFlag = packetHeader.GetPacketHeader(url,offset);//�ж��Ƿ�����ļ�β

    if(!endFlag){
        return false;
    }
    else{
        std::cout<<"\n*****Packet Header*****\n";
        CapLen = packetHeader.AnalyzePacketHeader(pcapFlag);
        return true;
    }

}

void PcapFile::inputMacHeader(uint64_t &used_offset) {
//    std::cout<<offset<<std::endl;
    std::cout<<"*****Mac Header*****\n";
    macHeader.GetMacHeader(url,offset,used_offset);
    macHeader.AnalyzeMacHeader();

    if(macHeader.MacTypeflag == 0x800){
        inputIPv4Header(used_offset);
    }
    else if(macHeader.MacTypeflag == 0x86DD){
        inputIPv6Header(used_offset);
    }
    else if (macHeader.MacTypeflag == 0x0806){
        inputArpHeader(used_offset);
    }
}

void PcapFile::inputIPv4Header(uint64_t &used_offset) {
//    std::cout<<offset<<std::endl;
    std::cout<<"*****IPv4 Header*****\n";
    ipv4Header.GetIPHeader(url,offset,used_offset);
    ipv4Header.AnalyzeIPHeader(used_offset,ipTotalLen);

    if(ipv4Header.ipProtocolType == 6){
        inputTCPHeader(used_offset);
    }
    else if (ipv4Header.ipProtocolType == 1){
        inputICMPHeader(used_offset);
    }
    else if(ipv4Header.ipProtocolType == 17){
        inputUDPHeader(used_offset);
    }
}

void PcapFile::inputIPv6Header(uint64_t &used_offset) {
//    std::cout<<offset<<std::endl;
    std::cout<<"*****IPv6 Header*****\n";

    ipv6Header.GetIPHeader(url,offset,used_offset);
    ipv6Header.AnalyzeIPHeader(ipTotalLen);

    if(ipv6Header.nextHeader == 6){
        inputTCPHeader(used_offset);
    }
    else if(ipv6Header.nextHeader == 1){
        inputICMPHeader(used_offset);
    }
    else if(ipv6Header.nextHeader == 17){
        inputUDPHeader(used_offset);
    }
}

void PcapFile::inputArpHeader(uint64_t &used_offset) {
    std::cout<<"*****Arp Header*****\n";
    arpHeader.GetArpHeader(url,offset,used_offset);
    arpHeader.AnalyzeArpHeader();
}

void PcapFile::inputICMPHeader(uint64_t &used_offset) {
    std::cout<<"*****ICMP Header*****\n";
    icmpHeader.GetICMPHeader(url,offset,used_offset);
    icmpHeader.AnalyzeICMPHeader();
    if(icmpHeader.errorFlag == true){//����İ����²�ip��
        if(macHeader.MacTypeflag == 0x800){
            inputIPv4Header(used_offset);
        }
        else if(macHeader.MacTypeflag == 0x86DD){
            inputIPv6Header(used_offset);
        }
    }
}

void PcapFile::inputTCPHeader(uint64_t &used_offset) {
//    std::cout<<offset<<std::endl;
    std::cout<<"*****TCP Header*****\n";
    tcpHeader.GetTCPHeader(url,offset,used_offset);
    tcpHeader.AnalyzeTCPHeader(used_offset,ipTotalLen);

    if(tcpHeader.tcp_flags == 0x18 && tcpHeader.destination_port == 80){//PSH,ACK  80�˿�http����
        std::cout<<"*****Data GET*****\n";
        httpRequestData.GetData(url,offset,used_offset,ipTotalLen);
        httpRequestData.AnalyzeHTTPRequestData();
    }
    else if(tcpHeader.tcp_flags == 0x18 && tcpHeader.source_port == 80){//PSH,ACK  80�˿�http��Ӧ
        std::cout<<"*****Data GET*****\n";
        httpRespoundData.GetData(url,offset,used_offset,ipTotalLen);
        httpRespoundData.AnalyzeHTTPRespoundData();
    }
}

void PcapFile::inputUDPHeader(uint64_t &used_offset) {
    std::cout<<"*****UDP Header*****\n";
    udpHeader.GetUDPHeader(url,offset,used_offset);
    udpHeader.AnalyzeUDPHeader(ipTotalLen);

    if(udpHeader.destination_port == 53 || udpHeader.source_port == 53){//DNSЭ��
        std::cout<<"*****DNS Header*****\n";
        dnsHeader.GetDNSHeader(url,offset,used_offset);
        dnsHeader.AnalyzeDNSHeader(ipTotalLen);
//        std::cout<<ipTotalLen<<std::endl;
        if(dnsHeader.dns_Type == 0){//����
            std::cout<<"*****Data GET*****\n";
            dnsQueryData.GetData(url,offset,used_offset,ipTotalLen);
            dnsQueryData.AnalyzeDNSData(ipTotalLen);
        }
        else{//��Ӧ
            std::cout<<"*****Data GET*****\n";
            dnsRespoundData.GetData(url,offset,used_offset,ipTotalLen);
            dnsRespoundData.AnalyzeDNSData(ipTotalLen);
        }
    }

}

int main() {

    PcapFile pf;
    pf.inputFile();

    return 0;
}
