#include <iostream>
#include <fstream>
#include <string>
#include <deque>
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
#include <iomanip>

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

            if(cnt == 65){
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
    void displayDNSSession();
    void displayHTTPSession();
private:
    PcapHeader pcapHeader;
    PacketHeader packetHeader;
    MacHeader macHeader;
    IPv4Header ipv4Header;
    IPv6Header ipv6Header;
    Utilities utilities;

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

    std::map<uint64_t,std::deque<session_elements>> DNS_session;
    std::map<uint64_t,std::deque<session_elements>>::iterator it_dns;
    std::map<uint64_t,std::deque<session_elements_http>> HTTP_session;
    std::map<uint64_t,std::deque<session_elements_http>>::iterator it_http;

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
    ArpHeader arpHeader;
    arpHeader.GetArpHeader(url,offset,used_offset);
    arpHeader.AnalyzeArpHeader();
}

void PcapFile::inputICMPHeader(uint64_t &used_offset) {
    std::cout<<"*****ICMP Header*****\n";
    ICMPHeader icmpHeader;
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
    TCPHeader tcpHeader;
    tcpHeader.GetTCPHeader(url,offset,used_offset);
    tcpHeader.AnalyzeTCPHeader(used_offset,ipTotalLen);

    session_elements_http sessionElementsHttp;
    sessionElementsHttp.source_ip = ipv4Header.source_ip;
    sessionElementsHttp.destination_ip = ipv4Header.destination_ip;
    sessionElementsHttp.source_port = tcpHeader.source_port;
    sessionElementsHttp.destination_port = tcpHeader.destination_port;

    if(tcpHeader.tcp_flags == 0x18 && tcpHeader.destination_port == 80){//PSH,ACK  80�˿�http����
        std::cout<<"*****Data GET*****\n";

        HTTPRequestData httpRequestData;
        httpRequestData.GetData(url,offset,used_offset,ipTotalLen);
        httpRequestData.AnalyzeHTTPRequestData();

        sessionElementsHttp.message_type = 0;
        sessionElementsHttp.edition = httpRequestData.httpRequestLine.edition;
        sessionElementsHttp.method = httpRequestData.httpRequestLine.request_method;
        sessionElementsHttp.uri = httpRequestData.uri;
        sessionElementsHttp.body = httpRequestData.httpBody;

    }
    else if(tcpHeader.tcp_flags == 0x18 && tcpHeader.source_port == 80){//PSH,ACK  80�˿�http��Ӧ
        std::cout<<"*****Data GET*****\n";
        HTTPRespondData httpRespondData;
        httpRespondData.GetData(url,offset,used_offset,ipTotalLen);
        httpRespondData.AnalyzeHTTPRespondData();

        sessionElementsHttp.message_type = 1;
        sessionElementsHttp.edition = httpRespondData.httpStatusLine.edition;
        sessionElementsHttp.code = httpRespondData.httpStatusLine.code;
        sessionElementsHttp.reason = httpRespondData.httpStatusLine.reason;
        sessionElementsHttp.body = httpRespondData.httpBody;
    }
    uint64_t value_hash = utilities.HTTPHashFunction(sessionElementsHttp.source_ip,sessionElementsHttp.destination_ip,sessionElementsHttp.source_port,sessionElementsHttp.destination_port);
    HTTP_session[value_hash] .push_back(sessionElementsHttp);
}

void PcapFile::inputUDPHeader(uint64_t &used_offset) {
    std::cout<<"*****UDP Header*****\n";
    UDPHeader udpHeader;
    udpHeader.GetUDPHeader(url,offset,used_offset);
    udpHeader.AnalyzeUDPHeader(ipTotalLen);

    if(udpHeader.destination_port == 53 || udpHeader.source_port == 53){//DNSЭ��
        DNSHeader dnsHeader;
        std::cout<<"*****DNS Header*****\n";
        dnsHeader.GetDNSHeader(url,offset,used_offset);
        dnsHeader.AnalyzeDNSHeader(ipTotalLen);
        session_elements temp_elements;
        temp_elements.source_ip = ipv4Header.source_ip;
        temp_elements.destination_ip = ipv4Header.destination_ip;
        temp_elements.source_port = udpHeader.source_port;
        temp_elements.destination_port = udpHeader.destination_port;
        temp_elements.message_type = dnsHeader.dns_Type;
        std::string context;
//        std::cout<<ipTotalLen<<std::endl;
        if(dnsHeader.dns_Type == 0){//����
            std::cout<<"*****Data GET*****\n";
            DNSQueryData dnsQueryData;
            dnsQueryData.AnalyzeDNSData(url, offset, used_offset,ipTotalLen,DNS_session,dnsHeader.TransactionID);
            temp_elements.context = dnsQueryData.context;
            temp_elements.query_type_string = dnsQueryData.query_type_string;
        }
        else{//��Ӧ
            std::cout<<"*****Data GET*****\n";
            DNSRespondData dnsRespondData;
            dnsRespondData.AnalyzeDNSData(url,offset,used_offset,ipTotalLen,DNS_session,dnsHeader.TransactionID);
            temp_elements.query_type_string = dnsRespondData.query_type_string;
            temp_elements.context = dnsRespondData.context;
            temp_elements.cname = dnsRespondData.cname;
            temp_elements.address = dnsRespondData.address;
            temp_elements.nameserver = dnsRespondData.nameserver;
            temp_elements.mailbox = dnsRespondData.mailbox;
            temp_elements.query_type_string = dnsRespondData.query_type_string;
        }

        DNS_session[dnsHeader.TransactionID].push_back(temp_elements);
    }
}

/*
 * ��ʾHTTP�Ự
 */
void PcapFile::displayHTTPSession() {
    printf("**********HTTP�Ự**********\n");
    for(it_http = HTTP_session.begin();it_http != HTTP_session.end();it_http++){
        for(int i = 1;i <= 60;i++){
            std::cout<<"*";
        }
        std::cout<<std::endl;

        std::cout<<"*  HashID:"<<it_http->first<<std::endl;
        session_elements_http temp_request;
        session_elements_http temp_respond;
        bool flag_query = 0;
        bool flag_respond = 0;

        while(!it_http->second.empty()){
            if(it_http->second.front().message_type == 0){//��ѯ
//                std::cout<<"��ѯ"<<std::endl;
                flag_query = 1;
                temp_request = it_http->second.front();
            }
            else{//Ӧ��
//                std::cout<<"Ӧ��"<<std::endl;
                flag_respond = 1;
                temp_respond = it_http->second.front();
            }
            it_http->second.pop_front();
        }

        if(flag_query == 0){//û�в�ѯ����
            std::cout<<"*    ȱ�ٲ�ѯ����"<<std::endl;
            uint64_t source = temp_respond.source_ip;
            uint64_t des = temp_respond.destination_ip;
            std::cout<<"*\tip:"<<(source>>24)<<"."<<((source>>16) -((source>>24)<<8))<<"."<<((source%65536 - source%256)>>8)<<"."<<source%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_respond.source_port<<std::endl;
            std::cout<<"*\t\t|��"<<std::endl;
            std::cout<<"*\t\t"<<temp_respond.edition<<std::endl;
            std::cout<<"*\t\t��|"<<std::endl;
            std::cout<<"*\tip:"<<(des>>24)<<"."<<((des>>16) -((des>>24)<<8))<<"."<<((des%65536 - des%256)>>8)<<"."<<des%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_respond.destination_port<<std::endl;

            if(temp_respond.method != ""){
                std::cout<<"*\tRequest: Method:"<<temp_respond.method<<std::endl;
            }
            if(temp_respond.uri != ""){
                std::cout<<"*\tRequest: url:"<<temp_respond.uri<<std::endl;
            }
        }
        else{//�в�ѯ����
            if(flag_respond == 0) {
                std::cout<<"*    ȱ��Ӧ����"<<std::endl;
            }
            uint64_t source = temp_request.source_ip;
            uint64_t des = temp_request.destination_ip;
            std::cout<<"*\tip:"<<(source>>24)<<"."<<((source>>16) -((source>>24)<<8))<<"."<<((source%65536 - source%256)>>8)<<"."<<source%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_request.source_port<<std::endl;
            std::cout<<"*\t\t|��"<<std::endl;
            std::cout<<"*\t\t"<<temp_request.edition<<std::endl;
            std::cout<<"*\t\t��|"<<std::endl;
            std::cout<<"*\tip:"<<(des>>24)<<"."<<((des>>16) -((des>>24)<<8))<<"."<<((des%65536 - des%256)>>8)<<"."<<des%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_request.destination_port<<std::endl;

            if(temp_request.reason != ""){
                std::cout<<"*\tRespond: reason:"<<temp_request.reason<<std::endl;
            }
            if(temp_request.code != ""){
                std::cout<<"*\tRespond: Code:"<<temp_request.code<<std::endl;
            }

            if(flag_respond == 1) {
                if(temp_respond.method != ""){
                    std::cout<<"*\tRequest: Method:"<<temp_respond.method<<std::endl;
                }
                if(temp_respond.uri != ""){
                    std::cout<<"*\tRequest: url:"<<temp_respond.uri<<std::endl;
                }
            }
        }



        for(int i = 1;i <= 60;i++){
            std::cout<<"*";
        }
        std::cout<<std::endl<<std::endl;

    }
}


/*
 * ��ʾDNS�Ự
 */
void PcapFile::displayDNSSession() {
    printf("**********DNS�Ự**********\n");
    for(it_dns = DNS_session.begin();it_dns != DNS_session.end();it_dns++){
        for(int i = 1;i <= 60;i++){
            std::cout<<"*";
        }
        std::cout<<std::endl;

        std::cout<<"*  ID:"<<it_dns->first<<std::endl;

        session_elements temp_query;
        session_elements temp_respond;
        bool flag_query = 0;
        bool flag_respond = 0;

        while(!it_dns->second.empty()){
            if(it_dns->second.front().message_type == 0){//��ѯ
                flag_query = 1;
                temp_query = it_dns->second.front();
            }
            else{//Ӧ��
                flag_respond = 1;
                temp_respond = it_dns->second.front();
            }
            it_dns->second.pop_front();
        }

        if(flag_respond == 0){//û��Ӧ���ģ�ͨ����ѯ���Ļ�ȡ��Ϣ
            std::cout<<"*    ȱ��Ӧ����"<<std::endl;
            uint64_t source = temp_query.source_ip;
            uint64_t des = temp_query.destination_ip;
            std::cout<<"*\tip:"<<(source>>24)<<"."<<((source>>16) -((source>>24)<<8))<<"."<<((source%65536 - source%256)>>8)<<"."<<source%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_query.source_port<<std::endl;
            std::cout<<"*\t\t|��\tQuery Type:"<<temp_query.query_type_string<<std::endl;
            std::cout<<"*\t\t��|\tQuery Context:"<<temp_query.context<<std::endl;
            std::cout<<"*\tip:"<<(des>>24)<<"."<<((des>>16) -((des>>24)<<8))<<"."<<((des%65536 - des%256)>>8)<<"."<<des%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_query.destination_port<<std::endl;
        }
        else {//��Ӧ���ģ���ͨ��Ӧ���ȡ
            if (flag_query == 0){
                std::cout<<"ȱ�ٲ�ѯ����"<<std::endl;
            }
            uint64_t source = temp_respond.source_ip;
            uint64_t des = temp_respond.destination_ip;
            std::cout<<"*\tip:"<<(source>>24)<<"."<<((source>>16) -((source>>24)<<8))<<"."<<((source%65536 - source%256)>>8)<<"."<<source%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_respond.source_port<<std::endl;
            std::cout<<"*\t\t|��\tQuery Type:"<<temp_respond.query_type_string<<std::endl;
            std::cout<<"*\t\t��|\tQuery Context:"<<temp_respond.context<<std::endl;
            std::cout<<"*\tip:"<<(des>>24)<<"."<<((des>>16) -((des>>24)<<8))<<"."<<((des%65536 - des%256)>>8)<<"."<<des%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_respond.destination_port<<std::endl;

            if(temp_respond.cname != ""){
                std::cout<<"*\tAnswer Cname:"<<temp_respond.cname<<std::endl;
            }
            if(temp_respond.address != ""){
                std::cout<<"*\tAnswer Address:"<<temp_respond.address<<std::endl;
            }
            if(temp_respond.nameserver != ""){
                std::cout<<"*\tAnswer Primary name server:"<<temp_respond.nameserver<<std::endl;
            }
            if(temp_respond.mailbox != ""){
                std::cout<<"*\tAnswer Responsible authority's mailbox:"<<temp_respond.mailbox<<std::endl;
            }
        }
        for(int i = 1;i <= 60;i++){
            std::cout<<"*";
        }
        std::cout<<std::endl<<std::endl;

    }
}

int main() {

    PcapFile pf;
    pf.inputFile();
    pf.displayDNSSession();
//    pf.displayHTTPSession();
    return 0;
}
