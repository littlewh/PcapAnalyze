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
//        std::string url = "";//待分析的目标文件路径
//        std::cin>>url;
        url = "E:\\TestProject\\PcapAnalyze\\tcp-trace-1";
//        url = "E:\\TestProject\\PcapAnalyze\\2.pcap";
    }
    void inputFile(){
        inputPcapHeader();
        FILE *fp = fopen(url,"rb");//采用rb而不是r，因包是十六进制数据，存在0x1A，会被误认成EOF，导致读乱
        if (fp == NULL){
            printf("打开文件失败");
            return ;
        }
        int cnt = 0;//记录第几个包
        offset = 24;//到此 offset指向的是pcap文件头

        while(fseek(fp,offset,SEEK_SET) == 0){

//            std::cout<<offset<<std::endl;
            bool endFlag = inputPackHeader();//文件尾
            if(!endFlag){
                break;
            }
            cnt ++;

//            if(cnt == 65){
//                break;
//            }

            printf("\n**********第%d个包**********\n",cnt);
            offset += 16;//到此 offset指向的是packet包头

            uint64_t used_offset = 0;//记录偏移量

            if(pcapHeader.LinkTypeFlag == 1){//以太网帧
                inputMacHeader(used_offset);
            }

            offset +=  CapLen;//这样后面的就不能用引用，只是值传递即可
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
    bool pcapFlag;//判断大小端
    char *url;//文件路径
    uint64_t offset;//当前偏移量，为了fseek的定位使用
    uint64_t CapLen;
    /*
     * 负载长度
     * 为了防止出现存在mac帧尾的情况，不能使用Caplen计算payload，引入负载长度，从ip报文的length开始记录
     */
    uint64_t payloadLen;

    std::map<uint64_t,std::deque<session_elements>> DNS_session;
    std::map<uint64_t,std::deque<session_elements>>::iterator it_dns;
    std::map<uint64_t,std::deque<session_elements_http>> HTTP_session;
    std::map<uint64_t,std::deque<session_elements_http>>::iterator it_http;

    std::map<uint64_t,session_value> count_dns;
    std::map<uint64_t,session_value> count_http;

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


    bool endFlag = packetHeader.GetPacketHeader(url,offset);//判断是否读到文件尾

    if(!endFlag){
        return false;
    }
    else{
        std::cout<<"\n*****Packet Header*****\n";
        CapLen = packetHeader.AnalyzePacketHeader(pcapFlag);
        return true;
    }

}
/*
 * 输入mac
 */
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
/*
 * 输入IPv4
 */
void PcapFile::inputIPv4Header(uint64_t &used_offset) {
//    std::cout<<offset<<std::endl;
    std::cout<<"*****IPv4 Header*****\n";
    ipv4Header.GetIPHeader(url,offset,used_offset);
    ipv4Header.AnalyzeIPHeader(used_offset,payloadLen);

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

/*
 * 输入IPv6
 */
void PcapFile::inputIPv6Header(uint64_t &used_offset) {
//    std::cout<<offset<<std::endl;
    std::cout<<"*****IPv6 Header*****\n";

    ipv6Header.GetIPHeader(url,offset,used_offset);
    ipv6Header.AnalyzeIPHeader(payloadLen);

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
/*
 * 输入arp
 */
void PcapFile::inputArpHeader(uint64_t &used_offset) {
    std::cout<<"*****Arp Header*****\n";
    ArpHeader arpHeader;
    arpHeader.GetArpHeader(url,offset,used_offset);
    arpHeader.AnalyzeArpHeader();
}
/*
 * 输入ICMP
 */
void PcapFile::inputICMPHeader(uint64_t &used_offset) {
    std::cout<<"*****ICMP Header*****\n";
    ICMPHeader icmpHeader;
    icmpHeader.GetICMPHeader(url,offset,used_offset);
    icmpHeader.AnalyzeICMPHeader();
    if(icmpHeader.errorFlag == true){//差错报文包含下层ip报
        if(macHeader.MacTypeflag == 0x800){
            inputIPv4Header(used_offset);
        }
        else if(macHeader.MacTypeflag == 0x86DD){
            inputIPv6Header(used_offset);
        }
    }
}

/*
 * 输入tcp
 */
void PcapFile::inputTCPHeader(uint64_t &used_offset) {
//    std::cout<<offset<<std::endl;
    std::cout<<"*****TCP Header*****\n";
    TCPHeader tcpHeader;
    tcpHeader.GetTCPHeader(url,offset,used_offset);
    tcpHeader.AnalyzeTCPHeader(used_offset,payloadLen);

    session_elements_http sessionElementsHttp;
    sessionElementsHttp.source_ip = ipv4Header.source_ip;
    sessionElementsHttp.destination_ip = ipv4Header.destination_ip;
    sessionElementsHttp.source_port = tcpHeader.source_port;
    sessionElementsHttp.destination_port = tcpHeader.destination_port;
    uint64_t value_hash = utilities.HTTPHashFunction(sessionElementsHttp.source_ip,sessionElementsHttp.destination_ip,sessionElementsHttp.source_port,sessionElementsHttp.destination_port);

    bool valid_flag = false;

    if(tcpHeader.tcp_flags == 0x18 && tcpHeader.destination_port == 80){//PSH,ACK  80端口http请求
        std::cout<<"*****HTTP Data GET*****\n";

        HTTPRequestData httpRequestData;
        httpRequestData.GetData(url,offset,used_offset,payloadLen);
        valid_flag = httpRequestData.AnalyzeHTTPRequestData(value_hash,HTTP_session);

        count_http[value_hash].number_packet++;
        count_http[value_hash].number_query++;
        count_http[value_hash].number_bytes += payloadLen;


        sessionElementsHttp.message_type = 0;
        sessionElementsHttp.edition = httpRequestData.httpRequestLine.edition;
        sessionElementsHttp.method = httpRequestData.httpRequestLine.request_method;
        sessionElementsHttp.uri = httpRequestData.uri;
        sessionElementsHttp.body = httpRequestData.httpBody;

    }
    else if(tcpHeader.tcp_flags == 0x18 && tcpHeader.source_port == 80){//PSH,ACK  80端口http响应
        std::cout<<"*****HTTP Data GET*****\n";
        HTTPRespondData httpRespondData;
        httpRespondData.GetData(url,offset,used_offset,payloadLen);
        valid_flag = httpRespondData.AnalyzeHTTPRespondData(value_hash,HTTP_session);

        count_http[value_hash].number_packet++;
        count_http[value_hash].number_answer++;
        count_http[value_hash].number_bytes += payloadLen;

        sessionElementsHttp.message_type = 1;
        sessionElementsHttp.edition = httpRespondData.httpStatusLine.edition;
        sessionElementsHttp.code = httpRespondData.httpStatusLine.code;
        sessionElementsHttp.reason = httpRespondData.httpStatusLine.reason;
        sessionElementsHttp.body = httpRespondData.httpBody;
    }
    if(valid_flag){//有效报文入队
        HTTP_session[value_hash].push_back(sessionElementsHttp);
    }

}

/*
 * 输入udp
 */

void PcapFile::inputUDPHeader(uint64_t &used_offset) {
    std::cout<<"*****UDP Header*****\n";
    UDPHeader udpHeader;
    udpHeader.GetUDPHeader(url,offset,used_offset);
    udpHeader.AnalyzeUDPHeader(payloadLen);

    if(udpHeader.destination_port == 53 || udpHeader.source_port == 53){//DNS协议
        DNSHeader dnsHeader;
        std::cout<<"*****DNS Header*****\n";

        dnsHeader.GetDNSHeader(url,offset,used_offset);
        uint64_t  temp_payloadLen = payloadLen;
        dnsHeader.AnalyzeDNSHeader(payloadLen);
        session_elements temp_elements;
        temp_elements.source_ip = ipv4Header.source_ip;
        temp_elements.destination_ip = ipv4Header.destination_ip;
        temp_elements.source_port = udpHeader.source_port;
        temp_elements.destination_port = udpHeader.destination_port;
        temp_elements.message_type = dnsHeader.dns_Type;
        std::string context;
//        std::cout<<ipTotalLen<<std::endl;

        count_dns[dnsHeader.TransactionID].number_bytes += temp_payloadLen;
        count_dns[dnsHeader.TransactionID].number_packet++;

        if(dnsHeader.dns_Type == 0){//请求
            std::cout<<"*****DNS Data GET*****\n";
            DNSQueryData dnsQueryData;
            dnsQueryData.AnalyzeDNSData(url, offset, used_offset,payloadLen,DNS_session,dnsHeader.TransactionID);
            temp_elements.context = dnsQueryData.context;
            temp_elements.query_type_string = dnsQueryData.query_type_string;

            count_dns[dnsHeader.TransactionID].number_query++;
        }
        else{//响应
            std::cout<<"*****DNS Data GET*****\n";
            DNSRespondData dnsRespondData;
            dnsRespondData.AnalyzeDNSData(url,offset,used_offset,payloadLen,DNS_session,dnsHeader.TransactionID);
            temp_elements.query_type_string = dnsRespondData.query_type_string;
            temp_elements.context = dnsRespondData.context;
            temp_elements.cname = dnsRespondData.cname;
            temp_elements.address = dnsRespondData.address;
            temp_elements.nameserver = dnsRespondData.nameserver;
            temp_elements.mailbox = dnsRespondData.mailbox;
            temp_elements.query_type_string = dnsRespondData.query_type_string;

            count_dns[dnsHeader.TransactionID].number_answer++;
        }

        DNS_session[dnsHeader.TransactionID].push_back(temp_elements);
    }
}

/*
 * 显示HTTP会话
 */
void PcapFile::displayHTTPSession() {
    printf("**********HTTP会话**********\n");
    for(it_http = HTTP_session.begin();it_http != HTTP_session.end();it_http++){
        for(int i = 1;i <= 60;i++){
            std::cout<<"*";
        }
        std::cout<<std::endl;

        std::cout<<"*  HashID:"<<it_http->first<<std::endl;
        std::cout<<"*  共:"<<count_http[it_http->first].number_packet<<"个包"<<std::endl;
        std::cout<<"*  其中有:"<<count_http[it_http->first].number_query<<"个请求包,"<<count_http[it_http->first].number_answer<<"个应答包"<<std::endl;
        std::cout<<"*  共:"<<count_http[it_http->first].number_bytes<<"bytes"<<std::endl;

        session_elements_http temp_request;
        session_elements_http temp_respond;
        bool flag_query = 0;
        bool flag_respond = 0;

        while(!it_http->second.empty()){
            if(it_http->second.front().message_type == 0){//查询
//                std::cout<<"查询"<<std::endl;
                flag_query = 1;
                temp_request = it_http->second.front();
            }
            else{//应答
//                std::cout<<"应答"<<std::endl;
                flag_respond = 1;
                temp_respond = it_http->second.front();
            }
            it_http->second.pop_front();
        }

        if(flag_query == 0){//没有查询报文,又队列非空,则一定有响应报文
            std::cout<<"*    缺少查询报文"<<std::endl;
            uint64_t source = temp_respond.source_ip;
            uint64_t des = temp_respond.destination_ip;
            std::cout<<"*\tip:"<<(des>>24)<<"."<<((des>>16) -((des>>24)<<8))<<"."<<((des%65536 - des%256)>>8)<<"."<<des%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_respond.destination_port<<std::endl;
            std::cout<<"*\t\t|↑"<<std::endl;
            std::cout<<"*\t\t"<<temp_respond.edition<<std::endl;
            std::cout<<"*\t\t↓|"<<std::endl;
            std::cout<<"*\tip:"<<(source>>24)<<"."<<((source>>16) -((source>>24)<<8))<<"."<<((source%65536 - source%256)>>8)<<"."<<source%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_respond.source_port<<std::endl;

            if(temp_respond.code != ""){
                std::cout<<"*\tRespond: Code:"<<temp_respond.code<<std::endl;
            }
            if(temp_respond.reason != ""){
                std::cout<<"*\tRespond: reason:"<<temp_respond.reason<<std::endl;
            }
        }
        else{//有查询报文
            if(flag_respond == 0) {
                std::cout<<"*    缺少应答报文"<<std::endl;
            }
            uint64_t source = temp_request.source_ip;
            uint64_t des = temp_request.destination_ip;
            std::cout<<"*\tip:"<<(source>>24)<<"."<<((source>>16) -((source>>24)<<8))<<"."<<((source%65536 - source%256)>>8)<<"."<<source%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_request.source_port<<std::endl;
            std::cout<<"*\t\t|↑"<<std::endl;
            std::cout<<"*\t\t"<<temp_request.edition<<std::endl;
            std::cout<<"*\t\t↓|"<<std::endl;
            std::cout<<"*\tip:"<<(des>>24)<<"."<<((des>>16) -((des>>24)<<8))<<"."<<((des%65536 - des%256)>>8)<<"."<<des%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_request.destination_port<<std::endl;

            if(temp_request.method != ""){
                std::cout<<"*\tRequest: Method:"<<temp_request.method<<std::endl;
            }
            if(temp_request.uri != ""){
                std::cout<<"*\tRequest: url:"<<temp_request.uri<<std::endl;
            }
            if(temp_request.content_type != ""){
                std::cout<<"*\tRequest: "<<temp_request.content_type<<std::endl;
            }

            if(flag_respond == 1) {
                if(temp_respond.code != ""){
                    std::cout<<"*\tRespond: Code:"<<temp_respond.code<<std::endl;
                }
                if(temp_respond.reason != ""){
                    std::cout<<"*\tRespond: reason:"<<temp_respond.reason<<std::endl;
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
 * 显示DNS会话
 */
void PcapFile::displayDNSSession() {
    printf("**********DNS会话**********\n");
    for(it_dns = DNS_session.begin();it_dns != DNS_session.end();it_dns++){
        for(int i = 1;i <= 60;i++){
            std::cout<<"*";
        }
        std::cout<<std::endl;

        std::cout<<"*  ID:"<<it_dns->first<<std::endl;
        std::cout<<"*  共:"<<count_dns[it_dns->first].number_packet<<"个包"<<std::endl;
        std::cout<<"*  其中有:"<<count_dns[it_dns->first].number_query<<"个请求包,"<<count_dns[it_dns->first].number_answer<<"个应答包"<<std::endl;
        std::cout<<"*  共:"<<count_dns[it_dns->first].number_bytes<<"bytes"<<std::endl;

        session_elements temp_query;
        session_elements temp_respond;
        bool flag_query = 0;
        bool flag_respond = 0;

        while(!it_dns->second.empty()){
            if(it_dns->second.front().message_type == 0){//查询
                flag_query = 1;
                temp_query = it_dns->second.front();
            }
            else{//应答
                flag_respond = 1;
                temp_respond = it_dns->second.front();
            }
            it_dns->second.pop_front();
        }

        if(flag_respond == 0){//没有应答报文，通过查询报文获取信息
            std::cout<<"*    缺少应答报文"<<std::endl;
            uint64_t source = temp_query.source_ip;
            uint64_t des = temp_query.destination_ip;
            std::cout<<"*\tip:"<<(source>>24)<<"."<<((source>>16) -((source>>24)<<8))<<"."<<((source%65536 - source%256)>>8)<<"."<<source%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_query.source_port<<std::endl;
            std::cout<<"*\t\t|↑\tQuery Type:"<<temp_query.query_type_string<<std::endl;
            std::cout<<"*\t\t↓|\tQuery Context:"<<temp_query.context<<std::endl;
            std::cout<<"*\tip:"<<(des>>24)<<"."<<((des>>16) -((des>>24)<<8))<<"."<<((des%65536 - des%256)>>8)<<"."<<des%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_query.destination_port<<std::endl;
        }
        else {//有应答报文，则通过应答获取
            if (flag_query == 0){
                std::cout<<"缺少查询报文"<<std::endl;
            }
            uint64_t source = temp_respond.source_ip;
            uint64_t des = temp_respond.destination_ip;
            std::cout<<"*\tip:"<<(des>>24)<<"."<<((des>>16) -((des>>24)<<8))<<"."<<((des%65536 - des%256)>>8)<<"."<<des%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_respond.destination_port<<std::endl;
            std::cout<<"*\t\t|↑\tQuery Type:"<<temp_respond.query_type_string<<std::endl;
            std::cout<<"*\t\t↓|\tQuery Context:"<<temp_respond.context<<std::endl;
            std::cout<<"*\tip:"<<(source>>24)<<"."<<((source>>16) -((source>>24)<<8))<<"."<<((source%65536 - source%256)>>8)<<"."<<source%256;
            std::cout<<std::right<<std::setw(10)<<"\t"<<"port:"<<temp_respond.source_port<<std::endl;

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
    pf.displayHTTPSession();

    return 0;
}
