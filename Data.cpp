//
// Created by admin on 2022/8/1.
//

#include "Data.h"
#include "Utilities.h"
#include <string>
/*
 * 获取HTTP数据
 */
bool Data::GetData(char *url, uint64_t offset, uint64_t &used_offset, uint64_t payload) {
    char data[payload];
    bool flag = utilities.inputHeader(url,offset,used_offset,payload,data);
    message_data = data;
//    std::cout<<payload<<std::endl;
//    std::cout<<message_data<<std::endl;

    return flag;
}

/*
 * 分析http请求报文
 */

void HTTPRequestData::AnalyzeHTTPRequestData() {
    //请求行

    std::string::size_type pos_start_line = message_data.find("\r\n");
//    std::cout<<pos_start_line;
    std::string start_line = message_data.substr(0,pos_start_line);

    std::string::size_type pos_target = start_line.find(" ");
//  std::cout<<pos_target;
    httpRequestLine.request_method = start_line.substr(0,pos_target);
    if(httpRequestLine.request_method != "POST" && httpRequestLine.request_method != "GET"){
        return;
    }
    std::cout<<"请求行:"<<std::endl;
    std::cout<<"Method:"<<httpRequestLine.request_method<<std::endl;

    std::string::size_type pos_edition = start_line.find_last_of(" ");
//  std::cout<<pos_edition;
    httpRequestLine.request_target = start_line.substr(pos_target+1,pos_edition-pos_target-1);
    std::cout<<"Request Target:"<<httpRequestLine.request_target<<std::endl;

    httpRequestLine.edition = start_line.substr(pos_edition+1,pos_start_line-pos_edition-1);
    std::cout<<"Edition:"<<httpRequestLine.edition<<std::endl;


    //请求头
    std::cout<<"请求头"<<std::endl;
    std::string::size_type pos_header = message_data.find_last_of("\r\n\r\n");//文件开始有一个空行，所以倒着找
//    std::cout<<pos_header;
    httpHeader = message_data.substr(pos_start_line+1,pos_header);
//    std::cout<<httpHeader<<std::endl;

    std::string host = utilities.findItemInData("Host:","\r\n",httpHeader);
    std::cout<<host<<std::endl;

    std::string agent = utilities.findItemInData("User-Agent:","\r\n",httpHeader);
    std::cout<<agent<<std::endl;

    std::string accept = utilities.findItemInData("Accept:","\r\n",httpHeader);
    std::cout<<accept<<std::endl;

    std::string Accept_Language = utilities.findItemInData("Accept-Language:","\r\n",httpHeader);
    std::cout<<Accept_Language<<std::endl;

    std::string Accept_Encoding = utilities.findItemInData("Accept-Encoding:","\r\n",httpHeader);
    std::cout<<Accept_Encoding<<std::endl;

    std::string Accept_Charset = utilities.findItemInData("Accept-Charset:","\r\n",httpHeader);
    std::cout<<Accept_Charset<<std::endl;

    std::string Connection = utilities.findItemInData("Connection:","\r\n",httpHeader);
    std::cout<<Connection<<std::endl;

//    std::cout<<httpHeader<<std::endl;

    std::cout<<"请求体"<<std::endl;
    httpBody = message_data.substr(pos_header+1);
    std::cout<<httpBody<<std::endl;

}

/*
 * 分析http响应报文
 */

void HTTPRespoundData::AnalyzeHTTPRespoundData() {
//    std::cout<<message_data<<std::endl;
    //响应行

    std::string::size_type pos_start_line = message_data.find("\r\n");
//    std::cout<<pos_start_line;
    std::string start_line = message_data.substr(0,pos_start_line);

    std::string::size_type pos_target = start_line.find(" ");
//  std::cout<<pos_target;
    httpStatusLine.edition = start_line.substr(0,pos_target);
    if(httpStatusLine.edition.find("HTTP") == httpStatusLine.edition.npos){
        return;
    }
    std::cout<<"响应行:"<<std::endl;
    std::cout<<"Edition:"<<httpStatusLine.edition<<std::endl;

    std::string::size_type pos_edition = start_line.find_last_of(" ");
//  std::cout<<pos_edition;
    httpStatusLine.code = start_line.substr(pos_target+1,pos_edition-pos_target-1);
    std::cout<<"Code:"<<httpStatusLine.code<<std::endl;

    httpStatusLine.reason = start_line.substr(pos_edition+1,pos_start_line-pos_edition-1);
    std::cout<<"Reason:"<<httpStatusLine.reason<<std::endl;


    //响应头
    std::cout<<"响应头"<<std::endl;
    std::string::size_type pos_header = message_data.find("\r\n\r\n");
//    std::cout<<pos_header;
    httpHeader = message_data.substr(pos_start_line+1,pos_header);
//    std::cout<<httpHeader<<std::endl;

    std::string server = utilities.findItemInData("Server:","\r\n",httpHeader);
    std::cout<<server<<std::endl;

    std::string date = utilities.findItemInData("Date:","\r\n",httpHeader);
    std::cout<<date<<std::endl;

    std::string content_type = utilities.findItemInData("Content-Type:","\r\n",httpHeader);
    std::cout<<content_type<<std::endl;

    std::string Accept_Encoding = utilities.findItemInData("Accept-Encoding:","\r\n",httpHeader);
    std::cout<<Accept_Encoding<<std::endl;

//    std::cout<<httpHeader<<std::endl;

    std::cout<<"响应体"<<std::endl;
    httpBody = message_data.substr(pos_header+1);
    std::cout<<httpBody<<std::endl;

}

/*
 * 分析DNS查询报文
 */

void DNSQueryData::AnalyzeDNSData(uint64_t payload) {
//    pre = payload;
    for(int i = 1;i < payload-5;i++){
        if(message_data[i] < 'a' || message_data[i] > 'z'){
            std::cout<<".";
        }
        else{
            std::cout<<message_data[i];
        }
    }
    printf("\n");

    printf("Type:");
    uint64_t type = 0;
    for(int i = payload-4;i < payload-2;i++){
        type <<= 8;
        type += 48+message_data[i]-'0';
        printf("%x",message_data[i]);
    }
    std::cout<<"("<<map_Type[type]<<")"<<std::endl;
    printf("Class:");
    uint64_t Class = 0;
    for(int i = payload-2;i < payload;i++){
        Class <<= 8;
        Class += 48+message_data[i]-'0';
        printf("%x",message_data[i]);
    }
    std::cout<<"("<<map_Class[Class]<<")"<<std::endl;
}

/*
 * 分析DNS响应报文
 */

void DNSRespoundData::AnalyzeDNSData(uint64_t payload) {
//    std::cout<<pre;
}