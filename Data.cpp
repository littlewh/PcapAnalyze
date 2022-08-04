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
    uint8_t data[payload];
    bool flag = utilities.inputHeader(url,offset,used_offset,payload,data);
    for(int i = 0;i < payload;i++){
        printf("%02x ",data[i]);
    }
    printf("\n");
    message_data = (char*)data;
//    for(int i = 0;i < payload;i++){
//        printf("%02x ",(uint8_t)message_data[i]);
//    }

//    std::cout<<payload<<std::endl;
//    std::cout<<message_data<<std::endl;

    return flag;
}

/*
 * 分析http请求报文
 */

void HTTPRequestData::AnalyzeHTTPRequestData() {
    //请求行

    std::string::size_type pos_start_line = message_data.find(0x0d0a);//换行
//    std::cout<<pos_start_line;
    std::string start_line = message_data.substr(0,pos_start_line);
//    std::cout<<"start line"<<start_line<<std::endl;
    std::string::size_type pos_target = start_line.find(0x20);//空格
//  std::cout<<pos_target;
    httpRequestLine.request_method = start_line.substr(0,pos_target);
    /*
     * @TODO:分包合并
     */
    if(httpRequestLine.request_method != "POST" && httpRequestLine.request_method != "GET"){
        return;
    }
    std::cout<<"请求行:"<<std::endl;
    std::cout<<"Method:"<<httpRequestLine.request_method<<std::endl;

    std::string::size_type pos_edition = start_line.find_last_of(0x20);//空格
//  std::cout<<pos_edition;
    httpRequestLine.request_target = start_line.substr(pos_target+1,pos_edition-pos_target-1);
    std::cout<<"Request Target:"<<httpRequestLine.request_target<<std::endl;

    httpRequestLine.edition = start_line.substr(pos_edition+1,pos_start_line-pos_edition-1);
    std::cout<<"Edition:"<<httpRequestLine.edition<<std::endl;


    //请求头
    std::cout<<"请求头:"<<std::endl;
    std::string::size_type pos_header = message_data.find("\r\n\r\n");//空行
//    std::cout<<pos_header<<std::endl;
    if(pos_header != message_data.npos){
        httpHeader = message_data.substr(pos_start_line+1,pos_header);
    }
    else{//报文没有结束
//        std::cout<<"NO"<<std::endl;
        httpHeader = message_data.substr(pos_start_line+1);
    }
//    std::cout<<pos_header;

//    std::cout<<httpHeader<<std::endl;

    std::string host = utilities.findItemInData("Host:","\r\n",httpHeader);
    std::cout<<host<<std::endl;
    uri = host;
    uri += httpRequestLine.request_target;

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

    if(pos_header != message_data.npos){
        std::cout<<"请求体:"<<std::endl;
        httpBody = message_data.substr(pos_header+1);
        std::cout<<httpBody<<std::endl;
    }
    else{//报文没有结束
//        std::cout<<"NO"<<std::endl;

    }
}

/*
 * 分析http响应报文
 */

void HTTPRespondData::AnalyzeHTTPRespondData() {
//    std::cout<<message_data<<std::endl;
    //响应行

    std::string::size_type pos_start_line = message_data.find("\r\n");
//    std::cout<<pos_start_line;
    std::string start_line = message_data.substr(0,pos_start_line);

    std::string::size_type pos_target = start_line.find(" ");
//  std::cout<<pos_target;
    std::string ss_edition = start_line.substr(0,pos_target);
    /*
     * @TODO:分包合并
     */
    if(ss_edition.find("HTTP") == ss_edition.npos){
        return;
    }
    std::cout<<"响应行:"<<std::endl;
    httpStatusLine.edition = ss_edition;
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
    std::cout<<pos_header<<std::endl;
    if(pos_header != message_data.npos){
        httpHeader = message_data.substr(pos_start_line+1,pos_header);
    }
    else{//报文没有结束
//        std::cout<<"NO"<<std::endl;
        httpHeader = message_data.substr(pos_start_line+1);
    }
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
    if(pos_header != message_data.npos){
        std::cout<<"响应体"<<std::endl;
        httpBody = message_data.substr(pos_header+1);
        std::cout<<httpBody<<std::endl;
    }
    else{//报文没有结束
//        std::cout<<"NO"<<std::endl;

    }


}

/*
 * 分析DNS查询报文
 */

void DNSQueryData::AnalyzeDNSData(char *url, uint64_t offset, uint64_t &used_offset,uint64_t payload,std::map<uint64_t,std::deque<session_elements>> &DNS_session,uint64_t TransactionID) {
    uint8_t data[payload];
    utilities.inputHeader(url,offset,used_offset,payload,data);
    for(int i = 0;i < payload;i++){
        printf("%02x ",data[i]);
    }
    printf("\n");
    context = "";
    for(int i = 1;i < payload-5;i++){
        if((data[i] >= 'a' && data[i] <= 'z') || data[i] == '_' || (data[i] >= '0' && data[i] <= '9')){
            std::cout<<data[i];
            context += data[i];
        }
        else{
            std::cout<<".";
            context += '.';
        }
    }
    printf("\n");

    printf("Type:");
    uint64_t query_type = 0;
    for(int i = payload-4;i < payload-2;i++){
        query_type <<= 8;
        query_type += 48+(uint8_t)data[i]-'0';
        printf("%x",(uint8_t)data[i]);
    }
    query_type_string = map_Type[query_type];
    std::cout<<"("<<map_Type[query_type]<<")"<<std::endl;
    printf("Class:");
    uint64_t Class = 0;
    for(int i = payload-2;i < payload;i++){
        Class <<= 8;
        Class += 48+(uint8_t)data[i]-'0';
        printf("%x",(uint8_t)data[i]);
    }
    std::cout<<"("<<map_Class[Class]<<")"<<std::endl;
}

/*
 * 分析DNS响应报文
 */

void DNSRespondData::AnalyzeDNSData(char *url, uint64_t offset, uint64_t &used_offset,uint64_t payload,std::map<uint64_t,std::deque<session_elements>> &DNS_session,uint64_t TransactionID) {
//    std::cout<<pre;
//    std::cout<<message_data<<std::endl;

    uint8_t data[payload];
    utilities.inputHeader(url,offset,used_offset,payload,data);
    for(int i = 0;i < payload;i++){
        printf("%02x ",data[i]);
    }
    printf("\n");

    if(DNS_session[TransactionID].empty()){
        std::cout<<"Meaningless Message！"<<std::endl;
    }
    else{
        uint64_t length = DNS_session[TransactionID].front().context.length();
        length += 2;

//        std::cout<<length<<" "<<DNS_session[TransactionID].front().context<<std::endl;

        context = "";
        for(int i = 1;i < length-1;i++){
            if((data[i] >= 'a' && data[i] <= 'z') || data[i] == '_' || (data[i] >= '0' && data[i] <= '9')){
                std::cout<<data[i];
                context += (char)data[i];
            }
            else{
                std::cout<<".";
                context += '.';
            }
        }
        printf("\n");

        printf("Type:");
        uint64_t query_type = 0;
        for(int i = length;i < length+2;i++){
            query_type <<= 8;
            query_type += 48+(uint8_t)data[i]-'0';
            printf("%x",(uint8_t)data[i]);
        }
        query_type_string = map_Type[query_type];
        std::cout<<"("<<map_Type[query_type]<<")"<<std::endl;
        length += 2;

        printf("Class:");
        uint64_t Class = 0;
        for(int i = length;i < length+2;i++){
            Class <<= 8;
            Class += 48+(uint8_t)data[i]-'0';
            printf("%x",(uint8_t)data[i]);
        }
        std::cout<<"("<<map_Class[Class]<<")"<<std::endl;
        length += 2;

        payload -= length;
//        std::cout<<"payload"<<payload<<std::endl;

        cname = "";//避免累加上一次的内容
        address = "";
        mailbox = "";

        while(payload){
//            std::cout<<"payload"<<payload<<std::endl;
            uint8_t _name[2];
            _name[0] = data[length];
            _name[1] = data[length+1];
            uint64_t abridge_name = 48 + (_name[0]%64+_name[1]) -'0';//压缩后的域名标识符指示的位置
//            std::cout<<"ab"<< abridge_name<<std::endl;
            std::cout<<"\tNAME:";
            for(int i = abridge_name-11;;i++){
                if(data[i] == 0x00){
                    break;
                }
                else{
                    if((data[i] >= 'a' && data[i] <= 'z') || data[i] == '_' || (data[i] >= '0' && data[i] <= '9')){
                        std::cout<<data[i];
                    }
                    else{
                        std::cout<<".";
                    }
                }
            }
            std::cout<<std::endl;
            length += 2;//Name
            payload -= 2;

            uint64_t answer_type = 0;
            for(int i = length;i < length+2;i++){
                answer_type <<= 8;
                answer_type += 48+((uint8_t)data[i])-'0';
//                printf("%02x ",(uint8_t)message_data[i]);
            }
            length += 2;//Type
            payload -= 2;

            if(answer_type == 5){//CNAME
                std::cout<<"\tType:"<<map_Type[answer_type]<<":"<<std::endl;

                uint64_t data_length = utilities.DNSAnswerHeader(data,length,payload,map_Class);

                printf("CNAME:");

                for(int i = length+1;i < length+data_length-2;i++){
                    if(data[i] < 'a' || data[i] > 'z'){
                        std::cout<<".";
                        cname += '.';
                    }
                    else{
                        std::cout<<data[i];
                        cname += (char)data[i];
                    }
//                    printf("%02x ",(uint8_t)message_data[i]);
                }
                cname += ';';
                length += data_length;
                payload -= data_length;
//                std::cout<<"\npayload:"<<payload<<std::endl;
                printf("\n");

            }
            else if (answer_type == 1){
                std::cout<<"\tType:"<<map_Type[answer_type]<<":"<<std::endl;//Host

                uint64_t data_length = utilities.DNSAnswerHeader(data,length,payload,map_Class);

                printf("Address:");
                int cnt = 0;

                for(int i = length;i < length+data_length;i++){
                    cnt++;
                    address += std::to_string(48+data[i]-'0');
                    if(cnt <= 3){
                        address += '.';
                    }

                }
                std::cout<<address;
                address += ";";
                length += data_length;
                printf("\n");
            }
            else if (answer_type == 6){
                std::cout<<"\tType:"<<map_Type[answer_type]<<":"<<std::endl;//SOA

                uint64_t data_length = utilities.DNSAnswerHeader(data,length,payload,map_Class);

                bool flag = 0;
                for(int i = length+1;i < length+data_length-20;i++){
                    if((data[i] >= 'a' && data[i] <= 'z') || data[i] == '_' || (data[i] >= '0' && data[i] <= '9')){
                        if(flag){
                            mailbox += data[i];
                        }
                        else{
                            nameserver += data[i];
                        }
//                        std::cout<<data[i];
                    }

                    else{
                        if((data[i]>>6) == 3){
//                            std::cout<<"."<<context<<std::endl;
                            abridge_name = 48 + (data[i]%64+data[i+1]) -'0';
//                            std::cout<<"abr"<<abridge_name<<std::endl;
                            for(int j = abridge_name-12;;j++){
                                if(data[j] == 0x00){
                                    break;
                                }
                                else{
//                                    printf("%02x ",data[j]);
                                    if((data[j] >= 'a' && data[j] <= 'z') || data[j] == '_' || (data[j] >= '0' && data[j] <= '9')){
//                                        std::cout<<data[j];
                                        if(flag){
                                            mailbox += data[j];
                                        }
                                        else{
                                            nameserver += data[j];
                                        }
                                    }
                                    else{
//                                        std::cout<<".";
                                        if(flag){
                                            mailbox += ".";
                                        }
                                        else{
                                            nameserver += ".";
                                        }
                                    }
                                }
                            }
                            std::cout<<std::endl;
                            i += 2;
                            flag = 1;
                        }
                        else{
                            if(flag){
                                mailbox += ".";
                            }
                            else{
                                nameserver +=".";
                            }
//                            std::cout<<".";
                        }
                    }
                }
//                mailbox += "\bcom";
                std::cout<<"Primary name server:"<<nameserver<<std::endl;
                std::cout<<"Responsible authority's mailbox:"<<mailbox<<std::endl;

                printf("SerialNumber:");
                uint64_t snumber = 0;
                for(int i = length+data_length-20;i < length+data_length-16;i++){
                    snumber <<= 8;
                    snumber += 48+data[i]-'0';
                    printf("%02x",data[i]);
                }
                std::cout<<"("<<snumber<<")"<<std::endl;

                printf("RefreshInterval:");
                uint64_t refresh = 0;
                for(int i = length+data_length-16;i < length+data_length-12;i++){
                    refresh <<= 8;
                    refresh += 48+data[i]-'0';
                    printf("%02x",data[i]);
                }
                std::cout<<"("<<refresh<<" seconds)"<<std::endl;

                printf("RetryInterval:");
                uint64_t retry = 0;
                for(int i = length+data_length-12;i < length+data_length-8;i++){
                    retry <<= 8;
                    retry += 48+data[i]-'0';
                    printf("%02x",data[i]);
                }
                std::cout<<"("<<retry<<" seconds)"<<std::endl;

                printf("ExpireLimit:");
                uint64_t expire = 0;
                for(int i = length+data_length-8;i < length+data_length-4;i++){
                    expire <<= 8;
                    expire += 48+data[i]-'0';
                    printf("%02x",data[i]);
                }
                std::cout<<"("<<expire<<" seconds)"<<std::endl;

                printf("MinimumTTL:");
                uint64_t minttl = 0;
                for(int i = length+data_length-4;i < length+data_length;i++){
                    minttl <<= 8;
                    minttl += 48+data[i]-'0';
                    printf("%02x",data[i]);
                }
                std::cout<<"("<<minttl<<" seconds)"<<std::endl;

                length += data_length;
                payload -= data_length;
//                std::cout<<"\npayload:"<<payload<<std::endl;
                printf("\n");
            }
        }

    }
}