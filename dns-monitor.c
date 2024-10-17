#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <signal.h>  // Для обработки сигналов
#include <pcap.h>    // Для работы с pcap

#include "parse_args.h"

#define DNS_HEADER_SIZE 12

struct InputData input_data;


volatile int running = 1;  // Флаг работы программы
pcap_t *handle;            // Дескриптор pcap для захвата пакетов
struct bpf_program fp;
int in_offline = 0;
// DNS Header Structure
struct dns_header {
    unsigned short id; // идентификатор
    unsigned short flags;
    unsigned short qdcount; // количество вопросов
    unsigned short ancount; // количество ответов
    unsigned short nscount; // количество авторитетных записей
    unsigned short arcount; // количество дополнительных записей
};

int num_of_info = 0;

void terminate_program(int signal){
    if (signal == SIGINT || signal == SIGTERM || signal == SIGQUIT){
        pcap_breakloop(handle);  // Прерывание цикла pcap
        pcap_close(handle);
        printf("Program terminated gracefully.\n");
        pcap_freecode(&fp);
        exit(EXIT_SUCCESS);
    }else if (in_offline) {
        //print_traffic_offline();
        pcap_close(handle);
        printf("Program terminated gracefully.\n");
        pcap_freecode(&fp);
        exit(EXIT_SUCCESS);
    }
}

// Обработчик сигнала для завершения программы при нажатии Ctrl+C
void handle_sigint(int sig) {
    printf("\nCaught signal %d. Exiting...\n", sig);
    running = 0;
    pcap_breakloop(handle);  // Прерывание цикла pcap
}

// Функция для извлечения имени домена из DNS пакета
const u_char *extract_domain_name(const u_char *packet, const u_char *reader, char *domain_name) {
    int p = 0;  // Индекс для доменного имени
    int jumped = 0;  // Флаг, указывающий на то, что мы "прыгнули" в другое место
    int jump_offset = 0; // Переменная для хранения позиции при прыжке

    const u_char *orig_reader = reader; // Сохраняем оригинальный указатель для возврата, если прыгнули
    while (*reader != 0) {
        if (*reader >= 192) {  // Указатель на другую часть пакета
            /*if (!jumped) {
                jump_offset = reader - orig_reader + 2; // Сохраняем позицию после указателя (всегда 2 байта)
            }*/
            // Вычисляем смещение
            int offset = (*reader & 0x3F) << 8 | *(reader + 1);  // Получаем 14-битное смещение
            reader = packet + offset;  // Переход к указанному месту в пакете
            jumped = 1;  // Указываем, что мы "прыгнули"
        } else {
            // Добавляем сегмент доменного имени
            for (int i = 0; i < *reader; i++) {
                domain_name[p++] = *(reader + 1 + i);
            }
            domain_name[p++] = '.';  // Добавляем точку после сегмента            
        }
        reader += *reader + 1;  // Переход к следующему сегменту
    }

    domain_name[p-1] = '\0';  // Завершаем строку (убираем последнюю точку)

    

    // Если был "прыжок", возвращаемся на место, где был указатель
    if (jumped) {
        return orig_reader + 2;
    }

    return reader + 1;  // Возвращаем указатель на следующий байт после доменного имени
}

// Функция для вывода байтов в шестнадцатеричном виде
void print_hex(const u_char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

// Функция для обработки пакетов
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *iph = (struct ip *)(packet + 14);  // Смещение до IP заголовка
    struct udphdr *udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);  // Смещение до UDP заголовка
    struct dns_header *dnsh = (struct dns_header *)(packet + 14 + iph->ip_hl * 4 + sizeof(struct udphdr)); 

    char time_str[20]; 
    struct tm *ltime = localtime(&header->ts.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);  

    const u_char *ip_header = packet + 14;

    unsigned char protocol = ip_header[9];
    if (protocol != 17) { // 17 - это номер для UDP
        fprintf(stderr, "protocol is not udp\n");
        exit(EXIT_FAILURE);
    }

    // UDP заголовок после IP-заголовка (IP-заголовок = 20 байт)
    const u_char *udp_header = ip_header + 20;

    // Определяем порты (источник и получатель)
    unsigned short src_port = ntohs(*(unsigned short *)(udp_header));
    unsigned short dst_port = ntohs(*(unsigned short *)(udp_header + 2));

    // Проверяем, является ли это DNS пакетом
    if (src_port != 53 && dst_port != 53) {
        fprintf(stderr, "it is not udp packeges\n");
        exit(EXIT_FAILURE);
    }

    // DNS заголовок начинается после UDP заголовка (8 байт)
    const u_char *dns_header_data = udp_header + 8;
    struct dns_header *dns = (struct dns_header *)dns_header_data;

    /*printf("=======TESTING SECTIONS=======\n");

    // Выводим информацию из заголовка DNS
    printf("DNS ID: 0x%04x\n", ntohs(dns->id));
    printf("Flags: 0x%04x\n", ntohs(dns->flags));*/

    /*printf("Questions: %d\n", ntohs(dns->qdcount));
    printf("Answers: %d\n", ntohs(dns->ancount));
    printf("Authority RRs: %d\n", ntohs(dns->nscount));
    printf("Additional RRs: %d\n", ntohs(dns->arcount));*/

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
        const u_char *reader = dns_header_data + 12;  // Переход к Question секции
        char domain_name[1024];
        char cname_domain_name[1024];
        
        if(ntohs(dns->qdcount) >= 1){
            printf("\n[Question Section]\n");
        }
        const u_char *new_reader;

        for (int i = 0; i < ntohs(dns->qdcount); i++) {
            new_reader = reader;
            reader = extract_domain_name(packet, reader, domain_name);
            unsigned short qtype = ntohs(*(unsigned short *)reader);
            
            reader += 2; // Пропускаем тип
            unsigned short qclass = ntohs(*(unsigned short *)reader);
            reader += 2; // Пропускаем класс

            // Добавляем точку в конец доменного имени
            //printf("Question %d: %s., Type: %d, Class: %d\n", i + 1, domain_name, qtype, qclass);
            
            printf("%s. ", domain_name);
            if(qclass == 1){
                printf("IN ");
            }

            if(qtype == 1){
                printf("A\n");
            }else{
                printf("AAAA\n");
            }
        }


        if(ntohs(dns->ancount) >= 1){
            printf("\n[Answer Section]\n");
        }
        //reader = new_reader;
        // Обработка секции Answer
        
        for (int i = 0; i < ntohs(dns->ancount); i++) {
            printf("Raw before: %02x %02x\n", reader[0], reader[1]);
            reader = extract_domain_name(packet, reader, domain_name);
            printf("Raw before: %02x %02x\n", reader[0], reader[1]);

            //print_hex(packet, reader - packet); // Выводим байты доменного имени
            unsigned short atype = ntohs(*(unsigned short *)reader);
            reader += 2; // Пропускаем тип
            unsigned short aclass = ntohs(*(unsigned short *)reader);
            reader += 2; // Пропускаем класс
            unsigned int ttl = ntohl(*(unsigned int *)reader);
            reader += 4; // Пропускаем TTL
            unsigned short rdlength = ntohs(*(unsigned short *)reader);
            reader += 2; // Пропускаем длину данных

            const u_char *rdata = reader; // Начало RDATA            
            reader += rdlength; // Переход на следующую запись

            //printf("Answer %d: %s., Type: %d, Class: %d, TTL: %u, Data length: %d\n", i + 1, domain_name, atype, aclass, ttl, rdlength);
            printf("%s. ", domain_name);
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
            // Пример: если это A-запись (IPv4)
            if (atype == 1 && rdlength == 4) { // A запись (IPv4)
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
                const u_char *mx_data = rdata + 2; // Указатель на доменное имя почтового сервера

                char mx_domain_name[256];
                mx_data = extract_domain_name(packet, mx_data, mx_domain_name); // Извлекаем доменное имя
                printf("Priority: %u, Mail Server: %s\n", mx_priority, mx_domain_name);
            } else if (atype == 5 && rdlength > 0) { // CNAME запись
                
                //printf("Raw before: %02x %02x\n", reader[0], reader[1]);
                rdata = extract_domain_name(packet, rdata, cname_domain_name); // Извлекаем доменное имя
                printf("%s\n", cname_domain_name);
                //printf("Raw aafter: %02x %02x\n", reader[0], reader[1]);
                
            }else {
                //printf("\n");
                printf("atype: %d, rdlength: %d\n", atype, rdlength); // Просто переход на новую строку, если это не A или AAAA запись
            }
        }

    }

    if(ntohs(dns->nscount) >= 1){
        printf("\n[Authority  Section]\n");
    }

    if(ntohs(dns->arcount) >= 1){
        printf("\n[Additional  Section]\n");
    }
    //printf("[Question Section]\n");

    // Здесь будет код для разбора секции Question и вывода её содержимого.
    // Можно создать отдельную функцию для разбора записи.

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
        printf("=========\n");//delete
        handle = handle_interface(input_data);
    }else{
        printf("pcap file: %s\n", input_data.pcapfile);//delete
        printf("=========\n");//delete
        handle = handle_pcap_file(input_data);
    }

    
    if(pcap_loop(handle, 0, packet_handler, NULL) == -1){
        fprintf(stderr, "Error with pcap loop\n");
    }

    terminate_program(0);
    //pcap_close(handle);
    //printf("Program terminated gracefully.\n");
    //pcap_freecode(&fp);
}

// Основная функция
int main(int argc, char *argv[]) {
   
    input_data = parse_arguments(argc, argv);

    //signal(SIGINT, handle_sigint);

    printf("argc: %d\n", argc);
    
    start_monitoring(input_data);

    

    return 0;
}
