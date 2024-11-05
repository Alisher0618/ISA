#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>  // Для обработки сигналов
#include <pcap.h>    // Для работы с pcap
#include <arpa/nameser.h>
#include <resolv.h>
#include "parse_args.h"

#define ETHERTYPE_IP 0x0800
#define SKIP_IF_ETHERNET 42
#define SKIP_IF_SLL 44
#define DNS_HEADER_SIZE 12
#define SLL 0x8000
#define SIZE 256

struct InputData input_data;

int eth_sll = 0;


volatile int running = 1;  // Флаг работы программы
pcap_t *handle;            // Дескриптор pcap для захвата пакетов
struct bpf_program fp;
int in_offline = 0;
// DNS Header Structure
struct dns_header {
    unsigned short id; // идентификатор
    unsigned short flags;
    unsigned short qdcount; // number of questions
    unsigned short ancount; // number of answers
    unsigned short nscount; // number of authorities
    unsigned short arcount; // number of additional
};

FILE *file_domains, *file_translations;

int allowed_types[7] = {1, 2, 5, 6, 15, 28, 33};

int num_of_info = 0;
int write_domains;
int write_translations;

int jump_to_dns;

void terminate_program(int signal){
    if (signal == SIGINT || signal == SIGTERM || signal == SIGQUIT){
        pcap_breakloop(handle);  // Прерывание цикла pcap
        pcap_close(handle);
        //printf("Program terminated gracefully.\n");
    }else if (in_offline) {
        //print_traffic_offline();
        pcap_close(handle);
        //printf("Program terminated gracefully.\n");
    }else{
        pcap_close(handle);
        //printf("Program terminated gracefully.\n");
    }
    pcap_freecode(&fp);

    // Закрытие файла
    if (write_domains){
        fclose(file_domains);
    }
    
    if (write_translations){
        fclose(file_translations);
    }

    exit(EXIT_SUCCESS);
}

int domain_exists(char *domain) {
    char line[SIZE];
    while (fgets(line, sizeof(line), file_domains) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, domain) == 0) {
            return 1;
        }
    }
    return 0;
}

int translation_exists(char *domain, char* ip_address) {
    char line[SIZE];
    strcat(domain, " ");
    strcat(domain, ip_address);
    while (fgets(line, sizeof(line), file_translations) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, domain) == 0) {
            return 1;
        }
    }
    return 0;
}

void write_to_domain(char *domain_name){
    char domain[SIZE];
    strcpy(domain, domain_name);
    domain[strlen(domain)-1] = '\0';

    if(!domain_exists(domain)){
        fclose(file_domains);   //closing for reading
        file_domains = fopen(input_data.domainsfile, "a");
        
        fprintf(file_domains, "%s\n", domain);
        
        fclose(file_domains);   //closing for adding
        file_domains = fopen(input_data.domainsfile, "r");
    }
}

void write_to_translation(char *domain_name, char* ip_address){
    char row[SIZE];
    strcpy(row, domain_name);
    row[strlen(row)-1] = '\0';
    
    if(!translation_exists(row, ip_address)){
        fclose(file_translations);   //closing for reading
        file_translations = fopen(input_data.transfile, "a");
        
        fprintf(file_translations, "%s\n", row);
        //fprintf(file_translations, "%s\n", ip_address); 
        
        fclose(file_translations);   //closing for adding
        file_translations = fopen(input_data.transfile, "r");
    }
}


int isAllowedType(int checkType){
    for (int i = 0; i < 7; i++){
        if(checkType == allowed_types[i]){
            return 1;
        }
    }
    
    return 0;
}


// Функция для извлечения имени домена из DNS пакета
int jumped;  // Флаг, указывающий на то, что мы "прыгнули" в другое место
int is_soa;
const uint8_t *extract_domain_name(const uint8_t *packet, const uint8_t *reader, char *domain_name) {
    int p = 0;  // Индекс для доменного имени
    jumped = 0;
    const uint8_t *orig_reader = reader; // Сохраняем оригинальный указатель для возврата, если прыгнули
    char next[SIZE] = {0};
    int offset; 
    int step = 0;
    while (*reader != 0) {
        if (*reader == 0xC0){  // Указатель на другую часть пакета
            if(is_soa){
                orig_reader = reader;
                is_soa = 0;
            }
            offset = (*reader & 0x3F) << 8 | *(reader + 1);  // Получаем 14-битное смещение
            reader = packet + offset;  // Переход к указанному месту в пакете
            jumped = 1;  // Указываем, что мы "прыгнули"
            
        } else {
            // Добавляем сегмент доменного имени
            for (int i = 0; i < *reader; i++) {
                next[step++] = *(reader + 1 + i);
                domain_name[p++] = *(reader + 1 + i);
            }
            next[step++] = '.';  // Добавляем точку после сегмента  
            domain_name[p++] = '.';

            reader += *reader + 1;  // Переход к следующему сегменту 
        }
    }   

    domain_name[p] = '\0';  // Завершаем строку (убираем последнюю точку)

    if (jumped) {
        return orig_reader + 2;
    }

    return reader + 1;  // Возвращаем указатель на следующий байт после доменного имени
}

void print_domains(unsigned short type, unsigned short length, const uint8_t *rdata, const uint8_t *packet, char *domain_name){
    if (type == 1 && length == 4) { // A запись (IPv4)
        struct in_addr addr;
        memcpy(&addr, rdata, sizeof(struct in_addr));
        printf("%s\n", inet_ntoa(addr));
        if(write_translations){
            fclose(file_translations);
            file_translations = fopen(input_data.transfile, "r");

            write_to_translation(domain_name, inet_ntoa(addr));  
        }
    }
    else if (type == 2 && length > 0) { // NS (Name Server) запись
        char ns_domain_name[SIZE];
        extract_domain_name(packet + jump_to_dns, rdata, ns_domain_name);

        if(write_domains){
            fclose(file_domains);
            file_domains = fopen(input_data.domainsfile, "r");

            write_to_domain(ns_domain_name);
        }
        printf("%s\n", ns_domain_name);
    }
    else if (type == 28 && length == 16) { // AAAA запись (IPv6)
        char ipv6_addr[INET6_ADDRSTRLEN];
        struct in6_addr addr6;
        memcpy(&addr6, rdata, sizeof(struct in6_addr));
        inet_ntop(AF_INET6, &addr6, ipv6_addr, sizeof(ipv6_addr));
        printf("%s\n", ipv6_addr);

        if(write_translations){
            fclose(file_translations);
            file_translations = fopen(input_data.transfile, "r");

            write_to_translation(domain_name, ipv6_addr);    
        }
    }
    else if (type == 15 && length > 0) { // MX запись
        // MX-запись: первый байт - приоритет, следующий сегмент - доменное имя почтового сервера
        unsigned short mx_priority;
        memcpy(&mx_priority, rdata, sizeof(unsigned short)); // Читаем приоритет
        mx_priority = ntohs(mx_priority); // Преобразуем в сетевой порядок
        const uint8_t *mx_data = rdata + 2; // Указатель на доменное имя почтового сервера

        char mx_domain_name[SIZE];
        mx_data = extract_domain_name(packet + jump_to_dns, mx_data, mx_domain_name); // Извлекаем доменное имя
        printf("%u %s\n", mx_priority, mx_domain_name);
    }
    else if (type == 5 && length > 0) { // CNAME запись
        char cname_domain_name[SIZE];
        const uint8_t *cname_data = rdata; // Начало RDATA для CNAME
        cname_data = extract_domain_name(packet + jump_to_dns, cname_data, cname_domain_name); // Извлекаем доменное имя
        printf("%s\n", cname_domain_name);  
    }
    else if (type == 6) { // SOA (Start of Authority) запись
        char mname[SIZE], rname[SIZE];
        const uint8_t *vdata = rdata; 
        //printf("\n%02x %02x %02x %02x\n", rdata[0], rdata[1], rdata[2], rdata[3]);
        is_soa = 1;
        vdata = extract_domain_name(packet + jump_to_dns, vdata, mname); // Primary NS
        //printf(" %02x %02x %02x %02x\n", rdata[0], rdata[1], rdata[2], rdata[3]);
        if(jumped){
            vdata = extract_domain_name(packet + jump_to_dns, vdata, rname); // Responsible authority's mailbox
            jumped = 0;
        }else{
            vdata = extract_domain_name(packet + jump_to_dns, vdata, rname); // Responsible authority's mailbox
        }

        unsigned int serial = ntohl(*(unsigned int *)rdata); vdata += 4;
        unsigned int refresh = ntohl(*(unsigned int *)rdata); vdata += 4;
        unsigned int retry = ntohl(*(unsigned int *)rdata); vdata += 4;
        unsigned int expire = ntohl(*(unsigned int *)rdata); vdata += 4;
        unsigned int minimum = ntohl(*(unsigned int *)rdata); vdata += 4;

        if(write_domains){
            fclose(file_domains);
            file_domains = fopen(input_data.domainsfile, "r");

            write_to_domain(mname);
        }

        if(write_domains){
            fclose(file_domains);
            file_domains = fopen(input_data.domainsfile, "r");

            write_to_domain(rname);
        }

        printf("%s %s\n", mname, rname);
    }else if (type == 33) { // SRV запись
        const uint8_t *adata = rdata;
        unsigned short priority = ntohs(*(unsigned short *)adata); adata += 2;
        unsigned short weight = ntohs(*(unsigned short *)adata); adata += 2;
        unsigned short port = ntohs(*(unsigned short *)adata); adata += 2;
        
        char srv_domain_name[SIZE];
        adata = extract_domain_name(packet + jump_to_dns, adata, srv_domain_name); // Извлекаем целевой домен

        printf("%s\n", srv_domain_name);
    }
    else {
        printf("type: %d, length: %d\n", type, length); // Просто переход на новую строку, если это не A или AAAA запись
    }
}

const uint8_t *question_section(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name){
    int printSection = 1;
    for (int i = 0; i < number; i++) {
        //printf("\nreader before: %02x %02x %02x %02x\n", reader[0], reader[1], reader[2], reader[3]);
        reader = extract_domain_name(packet, reader, domain_name);
        unsigned short qtype = ntohs(*(unsigned short *)reader);
        
        reader += 2; // Пропускаем тип
        unsigned short qclass = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем класс

        if(isAllowedType(qtype)){
            if(printSection){
                printf("\n[Question Section]\n");
                printSection = 0;
            }

            if(write_domains){
                fclose(file_domains);
                file_domains = fopen(input_data.domainsfile, "r");

                write_to_domain(domain_name);
            }
            
            printf("%s ", domain_name);
            if(qclass == 1){
                printf("IN ");
            }

            if(qtype == 1){
                printf("A\n");
            }else if(qtype == 2){
                printf("NS\n");
            }else if(qtype == 5){
                printf("CNAME\n");
            }else if(qtype == 6){
                printf("SOA\n");
            }else if(qtype == 15){
                printf("MX\n");
            }else if(qtype == 28){
                printf("AAAA\n");
            }else if(qtype == 33){
                printf("SRV\n");
            }
        }
    }

    return reader;
}

const uint8_t *answer_section(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name){
    int printSection = 1;
    for (int i = 0; i < number; i++) {
        //printf("\nreader before: %02x %02x %02x %02x\n", reader[0], reader[1], reader[2], reader[3]);
        //printf("%s\n", domain_name);
        reader = extract_domain_name(packet + jump_to_dns, reader, domain_name);
        //printf("\nreader after: %02x %02x %02x %02x\n", reader[0], reader[1], reader[2], reader[3]);
        unsigned short atype = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем тип
        unsigned short aclass = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем класс
        unsigned int ttl = ntohl(*(unsigned int *)reader);
        reader += 4; // Пропускаем TTL
        unsigned short rdlength = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем длину данных

        const uint8_t *rdata = reader; // Начало RDATA  
        
        reader += rdlength; // Переход на следующую запись

        if(isAllowedType(atype)){
            if(printSection){
                printf("\n[Answer Section]\n");
                printSection = 0;
            }

            if(write_domains){
                fclose(file_domains);
                file_domains = fopen(input_data.domainsfile, "r");

                write_to_domain(domain_name);
            }

            printf("%s ", domain_name);
            printf("%u ", ttl);
            if(aclass == 1){
                printf("IN ");
            }

            if(atype == 1){
                printf("A ");
            }else if(atype == 2){
                printf("NS ");
            }else if(atype == 5){
                printf("CNAME ");
            }else if(atype == 6){
                printf("SOA ");
            }else if(atype == 15){
                printf("MX ");
            }else if(atype == 28){
                printf("AAAA ");
            }else if(atype == 33){
                printf("SRV ");
            }

            print_domains(atype, rdlength, rdata, packet, domain_name);
        }

        
        
        /*if (atype == 1 && rdlength == 4) { // A запись (IPv4)
            struct in_addr addr;
            memcpy(&addr, rdata, sizeof(struct in_addr));
            printf("%s\n", inet_ntoa(addr));
        }else if (atype == 28 && rdlength == 16) { // AAAA запись (IPv6)
            char ipv6_addr[INET6_ADDRSTRLEN];
            struct in6_addr addr6;
            memcpy(&addr6, rdata, sizeof(struct in6_addr));
            inet_ntop(AF_INET6, &addr6, ipv6_addr, sizeof(ipv6_addr));
            printf("%s\n", ipv6_addr);
        } else if (atype == 15 && rdlength > 0) { // MX запись
            // MX-запись: первый байт - приоритет, следующий сегмент - доменное имя почтового сервера
            unsigned short mx_priority;
            memcpy(&mx_priority, rdata, sizeof(unsigned short)); // Читаем приоритет
            mx_priority = ntohs(mx_priority); // Преобразуем в сетевой порядок
            const uint8_t *mx_data = rdata + 2; // Указатель на доменное имя почтового сервера

            char mx_domain_name[256];
            mx_data = extract_domain_name(packet + jump_to_dns, mx_data, mx_domain_name); // Извлекаем доменное имя
            printf("Priority: %u, Mail Server: %s\n", mx_priority, mx_domain_name);
        } else if (atype == 5 && rdlength > 0) { // CNAME запись
            char cname_domain_name[1024];
            const uint8_t *cname_data = rdata; // Начало RDATA для CNAME
            cname_data = extract_domain_name(packet + jump_to_dns, cname_data, cname_domain_name); // Извлекаем доменное имя
            printf("%s\n", cname_domain_name);  
        }else {
            printf("atype: %d, rdlength: %d\n", atype, rdlength); // Просто переход на новую строку, если это не A или AAAA запись
        }*/
    }
    return reader;

}

const uint8_t *authority_section(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name){
    int printSection = 1;
    for (int i = 0; i < number; i++) {
        reader = extract_domain_name(packet + jump_to_dns, reader, domain_name);

        unsigned short atype = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем тип
        unsigned short aclass = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем класс
        unsigned int ttl = ntohl(*(unsigned int *)reader);
        reader += 4; // Пропускаем TTL
        unsigned short rdlength = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем длину данных

        const uint8_t *rdata = reader; // Начало RDATA
        reader += rdlength; // Переход на следующую запись

        if(isAllowedType(atype)){
            if(printSection){
                printf("\n[Authority  Section]\n");
                printSection = 0;
            }

            if(write_domains){
                fclose(file_domains);
                file_domains = fopen(input_data.domainsfile, "r");

                write_to_domain(domain_name);
            }
            
            printf("%s ", domain_name);
            printf("%u ", ttl);
            if(aclass == 1){
                printf("IN ");
            }

            if(atype == 1){
                printf("A ");
            }else if(atype == 2){
                printf("NS ");
            }else if(atype == 5){
                printf("CNAME ");
            }else if(atype == 6){
                printf("SOA ");
            }else if(atype == 15){
                printf("MX ");
            }else if(atype == 28){
                printf("AAAA ");
            }else if(atype == 33){
                printf("SRV ");
            }

            print_domains(atype, rdlength, rdata, packet, domain_name);
        }

        /*if (atype == 2) { // NS (Name Server) запись
            char ns_domain_name[256];
            extract_domain_name(packet + jump_to_dns, rdata, ns_domain_name);
            printf("%s\n", ns_domain_name);
        } else if (atype == 1 && rdlength == 4) { // A запись (IPv4)
            struct in_addr addr;
            memcpy(&addr, rdata, sizeof(struct in_addr));
            printf("%s\n", inet_ntoa(addr));
        } else if (atype == 28 && rdlength == 16) { // AAAA запись (IPv6)
            char ipv6_addr[INET6_ADDRSTRLEN];
            struct in6_addr addr6;
            memcpy(&addr6, rdata, sizeof(struct in6_addr));
            inet_ntop(AF_INET6, &addr6, ipv6_addr, sizeof(ipv6_addr));
            printf("%s\n", ipv6_addr);
        } else if (atype == 6) { // SOA (Start of Authority) запись
            char mname[256], rname[256];
            rdata = extract_domain_name(packet + jump_to_dns, rdata, mname); // Primary NS
            rdata = extract_domain_name(packet + jump_to_dns, rdata, rname); // Responsible authority's mailbox

            unsigned int serial = ntohl(*(unsigned int *)rdata); rdata += 4;
            unsigned int refresh = ntohl(*(unsigned int *)rdata); rdata += 4;
            unsigned int retry = ntohl(*(unsigned int *)rdata); rdata += 4;
            unsigned int expire = ntohl(*(unsigned int *)rdata); rdata += 4;
            unsigned int minimum = ntohl(*(unsigned int *)rdata); rdata += 4;

            printf("SOA MNAME: %s, RNAME: %s, SERIAL: %u, REFRESH: %u, RETRY: %u, EXPIRE: %u, MINIMUM: %u\n",
                mname, rname, serial, refresh, retry, expire, minimum);
        }*/
        
    }

    return reader;
}

const uint8_t *additional_section(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name){
    int printSection = 1;
    for (int i = 0; i < number; i++) {
        reader = extract_domain_name(packet + jump_to_dns, reader, domain_name);

        unsigned short atype = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем тип
        unsigned short aclass = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем класс
        unsigned int ttl = ntohl(*(unsigned int *)reader);
        reader += 4; // Пропускаем TTL
        unsigned short rdlength = ntohs(*(unsigned short *)reader);
        reader += 2; // Пропускаем длину данных

        const uint8_t *rdata = reader; // Начало RDATA
        reader += rdlength; // Переход на следующую запись

        if(isAllowedType(atype)){
            if(printSection){
                printf("\n[Additional  Section]\n");
                printSection = 0;
            }

            if(write_domains){
                fclose(file_domains);
                file_domains = fopen(input_data.domainsfile, "r");

                write_to_domain(domain_name);
            }
            
            printf("%s ", domain_name);
            printf("%u ", ttl);
            if(aclass == 1){
                printf("IN ");
            }

            if(atype == 1){
                printf("A ");
            }else if(atype == 2){
                printf("NS ");
            }else if(atype == 5){
                printf("CNAME ");
            }else if(atype == 6){
                printf("SOA ");
            }else if(atype == 15){
                printf("MX ");
            }else if(atype == 28){
                printf("AAAA ");
            }else if(atype == 33){
                printf("SRV ");
            }

            print_domains(atype, rdlength, rdata, packet, domain_name);
        }

        /*if (atype == 2) { // NS (Name Server) запись
            char ns_domain_name[256];
            extract_domain_name(packet + jump_to_dns, rdata, ns_domain_name);
            printf("%s\n", ns_domain_name);
        } else if (atype == 1 && rdlength == 4) { // A запись (IPv4)
            struct in_addr addr;
            memcpy(&addr, rdata, sizeof(struct in_addr));
            printf("%s\n", inet_ntoa(addr));
        } else if (atype == 28 && rdlength == 16) { // AAAA запись (IPv6)
            char ipv6_addr[INET6_ADDRSTRLEN];
            struct in6_addr addr6;
            memcpy(&addr6, rdata, sizeof(struct in6_addr));
            inet_ntop(AF_INET6, &addr6, ipv6_addr, sizeof(ipv6_addr));
            printf("%s\n", ipv6_addr);
        } else if (atype == 6) { // SOA (Start of Authority) запись
            char mname[256], rname[256];
            rdata = extract_domain_name(packet + jump_to_dns, rdata, mname); // Primary NS
            rdata = extract_domain_name(packet + jump_to_dns, rdata, rname); // Responsible authority's mailbox

            unsigned int serial = ntohl(*(unsigned int *)rdata); rdata += 4;
            unsigned int refresh = ntohl(*(unsigned int *)rdata); rdata += 4;
            unsigned int retry = ntohl(*(unsigned int *)rdata); rdata += 4;
            unsigned int expire = ntohl(*(unsigned int *)rdata); rdata += 4;
            unsigned int minimum = ntohl(*(unsigned int *)rdata); rdata += 4;

            printf("SOA MNAME: %s, RNAME: %s, SERIAL: %u, REFRESH: %u, RETRY: %u, EXPIRE: %u, MINIMUM: %u\n",
                mname, rname, serial, refresh, retry, expire, minimum);
        }*/
        
    }

    return reader;
}

// Функция для обработки пакетов
void packet_handler(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet) {

    /*struct sll_header {
        uint16_t sll_family;   // Тип канала (AF_PACKET)
        uint16_t sll_protocol; // Протокол уровня 3
        uint8_t  sll_pkttype;   // Тип пакета
        uint8_t  sll_hatype;    // Тип канала
        uint16_t sll_halen;     // Длина адреса канала
        uint8_t  sll_addr[8];   // MAC адрес источника
        uint16_t sll_index;     // Индекс интерфейса
    };*/
    
    struct ether_header {
        uint8_t  ether_dhost[6]; // MAC-адрес назначения
        uint8_t  ether_shost[6]; // MAC-адрес источника
        uint16_t ether_type;      // Тип протокола
    };

    // Получаем указатель на заголовок Ethernet
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    //struct sll_header *sll_hdr = (struct sll_header *)packet;


    struct ip *iph;
    struct udphdr *udph;
    struct dns_header *dnsh;
    const uint8_t *ip_header;

    int dlt = pcap_datalink(handle);
    if(dlt == DLT_EN10MB){
        //printf("is ethernet\n");
        jump_to_dns = SKIP_IF_ETHERNET;
        iph = (struct ip *)(packet + 14);  // Смещение до IP заголовка
        udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);  // Смещение до UDP заголовка
        dnsh = (struct dns_header *)(packet + 14 + iph->ip_hl * 4 + sizeof(struct udphdr)); 
        ip_header = packet + 14;
    }else if(dlt == DLT_LINUX_SLL){
        //printf("is linux cooked\n");
        jump_to_dns = SKIP_IF_SLL;
        iph = (struct ip *)(packet + 16);  // Смещение до IP заголовка
        udph = (struct udphdr *)(packet + 16 + iph->ip_hl * 4);  // Смещение до UDP заголовка
        dnsh = (struct dns_header *)(packet + 16 + iph->ip_hl * 4 + sizeof(struct udphdr)); 
        ip_header = packet + 16;
    }
    
    char time_str[20]; 
    struct tm *ltime = localtime(&header->ts.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);  

    // UDP заголовок после IP-заголовка (IP-заголовок = 20 байт)
    const uint8_t *udp_header;
    if(ip_header[0] == 0x45){ // IPv4
        if (ip_header[9] != 17) { // 17 - это номер для UDP
            fprintf(stderr, "ERROR: Protocol is not udp\n");
            exit(EXIT_FAILURE);
        }
        udp_header = ip_header + 20;

    }/*else{
        printf("ipv6 +40\n");
        if (ip_header[6] != 17) { // 17 - это номер для UDP
            fprintf(stderr, "ERROR: Protocol is not udp\n");
            exit(EXIT_FAILURE);
        }
        udp_header = ip_header + 40;
    }*/

    // Определяем порты (источник и получатель)
    unsigned short src_port = ntohs(*(unsigned short * )(udp_header));
    unsigned short dst_port = ntohs(*(unsigned short * )(udp_header + 2));

    // Проверяем, является ли это DNS пакетом
    if (src_port != 53 && dst_port != 53) {
        fprintf(stderr, "it is not udp packeges\n");
        exit(EXIT_FAILURE);
    }

    // DNS заголовок начинается после UDP заголовка (8 байт)
    const uint8_t *dns_header_data = udp_header + 8;
    struct dns_header *dns = (struct dns_header *)dns_header_data;
    

    if(!input_data.verbose){
        printf("%s ", time_str);
        printf("%s ", inet_ntoa(iph->ip_src));
        printf("-> ");
        printf("%s ", inet_ntoa(iph->ip_dst));
        //printf("%s %s -> %s", time_str, inet_ntoa(iph->ip_src), inet_ntoa(iph->ip_dst));
        if(((ntohs(dnsh->flags) >> 15) & 0x1) == 0){
            printf(" (Q %d/%d/%d/%d)\n", ntohs(dns->qdcount), ntohs(dns->ancount), ntohs(dns->nscount), ntohs(dns->arcount));
        }else{
            printf(" (R %d/%d/%d/%d)\n", ntohs(dns->qdcount), ntohs(dns->ancount), ntohs(dns->nscount), ntohs(dns->arcount));
        }
    }else{
        num_of_info++;
        if(num_of_info != 1){
            printf("\n");
        }
        printf("Timestamp: %s\n", time_str);
        printf("SrcIP: %s\n", inet_ntoa(iph->ip_src));
        printf("DstIP: %s\n", inet_ntoa(iph->ip_dst));
        printf("SrcPort: UDP/%d\n", ntohs(udph->uh_sport));
        printf("DstPort: UDP/%d\n", ntohs(udph->uh_dport));
        printf("Identifier: 0x%04X\n", ntohs(dnsh->id));
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
            (ntohs(dnsh->flags) >> 15) & 0x1, // QR
            (ntohs(dnsh->flags) >> 11) & 0xF, // OPCODE
            (ntohs(dnsh->flags) >> 10) & 0x1, // AA
            (ntohs(dnsh->flags) >> 9) & 0x1,  // TC
            (ntohs(dnsh->flags) >> 8) & 0x1,  // RD
            (ntohs(dnsh->flags) >> 7) & 0x1,  // RA
            (ntohs(dnsh->flags) >> 5) & 0x1,  // AD
            (ntohs(dnsh->flags) >> 4) & 0x1,  // CD
            ntohs(dnsh->flags) & 0xF           // RCODE
        );
        // Читаем Question секцию
        const uint8_t *reader = dns_header_data + 12;  // Переход к Question секции
        char domain_name[SIZE];
        
        // Question Section
        if(ntohs(dns->qdcount) >= 1){
            reader = question_section(ntohs(dns->qdcount), packet, reader, domain_name);
        }
        
        // Answer Section
        if(ntohs(dns->ancount) >= 1){
            reader = answer_section(ntohs(dns->ancount), packet, reader, domain_name);
        }

        // Authority Section
        if(ntohs(dns->nscount) >= 1){
            reader = authority_section(ntohs(dns->nscount), packet, reader, domain_name);
        }

        // Additional Section
        if(ntohs(dns->arcount) >= 1){
            reader = additional_section(ntohs(dns->arcount), packet, reader, domain_name);
        }

        /*for (int i = 0; i < ntohs(dns->arcount); i++) {
            reader = extract_domain_name(packet + jump_to_dns, reader, domain_name);

            unsigned short atype = ntohs(*(unsigned short *)reader);
            reader += 2; // Пропускаем тип
            unsigned short aclass = ntohs(*(unsigned short *)reader);
            reader += 2; // Пропускаем класс
            unsigned int ttl = ntohl(*(unsigned int *)reader);
            reader += 4; // Пропускаем TTL
            unsigned short rdlength = ntohs(*(unsigned short *)reader);
            reader += 2; // Пропускаем длину данных

            const uint8_t *rdata = reader; // Начало RDATA
            reader += rdlength; // Переход на следующую запись

            printf("%s ", domain_name);
            printf("%u ", ttl);
            if(aclass == 1){
                printf("IN ");
            }

            if(atype == 1){
                printf("A ");
            }else if(atype == 28){
                printf("AAAA ");
            }else if(atype == 15){
                printf("MX ");
            }else if(atype == 5){
                printf("CNAME ");
            }else{
                printf("Unknown atype ");
            }

            if (atype == 1 && rdlength == 4) { // A запись (IPv4)
                struct in_addr addr;
                memcpy(&addr, rdata, sizeof(struct in_addr));
                printf("%s\n", inet_ntoa(addr));
            } 
            else if (atype == 28 && rdlength == 16) { // AAAA запись (IPv6)
                char ipv6_addr[INET6_ADDRSTRLEN];
                struct in6_addr addr6;
                memcpy(&addr6, rdata, sizeof(struct in6_addr));
                inet_ntop(AF_INET6, &addr6, ipv6_addr, sizeof(ipv6_addr));
                printf("%s\n", ipv6_addr);
            } 
            else if (atype == 15) { // MX запись
                unsigned short mx_priority;
                memcpy(&mx_priority, rdata, sizeof(unsigned short));
                mx_priority = ntohs(mx_priority);
                char mx_domain_name[256];
                extract_domain_name(packet + jump_to_dns, rdata + 2, mx_domain_name);
                printf("MX Priority: %d, Mail Server: %s\n", mx_priority, mx_domain_name);
            } else {
                printf("Unknown additional record type: %d\n", atype);
            }
        }*/
    
    }

    printf("====================\n");
}


pcap_t *handle_interface(struct InputData input_data){
    char errbuf[PCAP_ERRBUF_SIZE];  
    pcap_t *handle = NULL;
    handle = pcap_open_live(input_data.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    char filter_exp[] = "udp port 53";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);

    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    return handle;
}

pcap_t *handle_pcap_file(struct InputData input_data){
    char errbuf[PCAP_ERRBUF_SIZE];  
    pcap_t *handle = NULL;
    handle = pcap_open_offline(input_data.pcapfile, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    char filter_exp[] = "udp port 53";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);

    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    return handle;
}


void start_monitoring(struct InputData input_data){
    signal(SIGINT, terminate_program);
    signal(SIGTERM, terminate_program);
    signal(SIGQUIT, terminate_program);
    printf("-i: %s\n-p: %s\n-v: %s\n-d: %s\n-t: %s\n", input_data.interface, input_data.pcapfile, 
                                                        (input_data.verbose ? "true" : "false"),
                                                        input_data.domainsfile, input_data.transfile);
    
    if(strcmp(input_data.interface, "none") != 0){
        printf("interface: %s\n", input_data.interface);//delete
        printf("=========\n\n");//delete
        handle = handle_interface(input_data);
    }else{
        printf("pcap file: %s\n", input_data.pcapfile);//delete
        printf("=========\n\n");//delete
        handle = handle_pcap_file(input_data);
    }

    if(input_data.domainsfile != NULL){
        write_domains = 1;
        file_domains = fopen(input_data.domainsfile, "w");
    
        // Проверка успешности открытия файла
        if (file_domains == NULL) {
            perror("Ошибка открытия файла");
            exit(EXIT_FAILURE);
        }    
    }

    if(input_data.transfile != NULL){
        write_translations = 1;
        file_translations = fopen(input_data.transfile, "w");
    
        // Проверка успешности открытия файла
        if (file_translations == NULL) {
            perror("Ошибка открытия файла");
            exit(EXIT_FAILURE);
        }    
    }

    
    if(pcap_loop(handle, 0, packet_handler, NULL) == -1){
        fprintf(stderr, "Error with pcap loop\n");
    }

    terminate_program(0);
}

int main(int argc, char *argv[]) {
   
    input_data = parse_arguments(argc, argv);

    printf("argc: %d\n", argc);
    
    start_monitoring(input_data);

    return 0;
}
