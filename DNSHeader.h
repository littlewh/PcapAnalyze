//
// Created by admin on 2022/8/2.
//

#ifndef PCAPANALYZE_DNSHEADER_H
#define PCAPANALYZE_DNSHEADER_H

#include <cstdint>
#include "Utilities.h"
/* ��12�ֽ�*/
struct dns_header{
    uint8_t TransactionID[2];//����id
    uint8_t Flags[2];//��־
    uint8_t Questions[2];//�������
    uint8_t AnswerRRs[2];//�ش���Դ��¼��
    uint8_t AuthorityRRs[2];//Ȩ�����Ʒ���������
    uint8_t AdditionalRRs[2];//������Դ��¼��
};
class DNSHeader {
public:
    DNSHeader(){
        dnsHeader = new dns_header();
        map_qr[0] = "��ѯ����";
        map_qr[1] = "��Ӧ����";

        map_code[0] = "��׼��ѯ";
        map_code[1] = "�����ѯ";
        map_code[2] = "������״̬����";

        map_aa[0] = "����Ȩ��������";
        map_aa[1] = "Ȩ��������";

        map_tc[0] = "���ɽضϵ�";
        map_tc[1] = "�ɽضϵ�";

        map_rd[0] = "������ѯ";
        map_rd[1] = "�ݹ��ѯ";

        map_ra[0] = "�����õݹ��ѯ";
        map_ra[1] = "���õݹ��ѯ";

        map_rcode[0] = "û�д���";
        map_rcode[1] = "���ĸ�ʽ����";
        map_rcode[2] = "����������ʧ��";
        map_rcode[3] = "���ִ���";
        map_rcode[4] = "��ѯ���Ͳ�֧��";
        map_rcode[5] = "�ܾ�";
    }
    bool GetDNSHeader(char *url,uint64_t offset,uint64_t &used_offset);//��ȡHeader����
    void AnalyzeDNSHeader(uint64_t &ipTotalLen);
    bool dns_Type;//0�ǲ�ѯ��1����Ӧ
    uint64_t TransactionID;//key
private:
    dns_header *dnsHeader;
    Utilities utilities;
    std::map<int,std::string> map_qr;
    std::map<int,std::string> map_code;
    std::map<int,std::string> map_aa;
    std::map<int,std::string> map_tc;
    std::map<int,std::string> map_rd;
    std::map<int,std::string> map_ra;
    std::map<int,std::string> map_rcode;
};


#endif //PCAPANALYZE_DNSHEADER_H
