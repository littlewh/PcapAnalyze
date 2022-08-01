//
// Created by admin on 2022/7/29.
//

#ifndef PCAPANALYZE_ICMPHEADER_H
#define PCAPANALYZE_ICMPHEADER_H
#include <cstdint>
#include <map>
/* ��8���ֽ� */

struct icmp_header{
    uint8_t Type;//����
    uint8_t Code;//����
    uint8_t CheckSum[2];//У���
    uint8_t Identifier[2];//��ʶ��
    uint8_t SequenceNumber[2];//���к�
};
class ICMPHeader {
public:
    ICMPHeader(){
        errorFlag = false;
        icmpHeader = new icmp_header();
        map_type[0] = "Ӧ��";
        map_type[3] = "�յ㲻�ɴ�";
        map_type[5] = "�ض���";
        map_type[8] = "��������";
        map_type[11] = "ʱ�䳬��";
        map_type[12] = "��������";
        map_type[13] = "ʱ�������";
        map_type[14] = "ʱ����ش�";

        map_code[0] = "����";
        map_code[1] = "����";
        map_code[2] = "Э��";
        map_code[3] = "�˿�";
    }
    bool GetICMPHeader(char *url,uint64_t offset,uint64_t &used_offset);//��ȡHeader����
    void AnalyzeICMPHeader();
    bool errorFlag;
private:
    icmp_header *icmpHeader;
    std::map<int,std::string> map_type;
    std::map<int,std::string> map_code;
};


#endif //PCAPANALYZE_ICMPHEADER_H
