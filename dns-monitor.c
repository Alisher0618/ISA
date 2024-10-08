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

volatile int running = 1;  // Флаг работы программы
pcap_t *handle;            // Дескриптор pcap для захвата пакетов

// DNS Header Structure
struct dns_header {
    unsigned short id; // идентификатор
    unsigned short flags;
    unsigned short qdcount; // количество вопросов
    unsigned short ancount; // количество ответов
    unsigned short nscount; // количество авторитетных записей
    unsigned short arcount; // количество дополнительных записей
};

// Обработчик сигнала для завершения программы при нажатии Ctrl+C
void handle_sigint(int sig) {
    printf("\nCaught signal %d. Exiting...\n", sig);
    running = 0;
    pcap_breakloop(handle);  // Прерывание цикла pcap
}

// Функция для обработки пакетов
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *iph = (struct ip *)(packet + 14);  // Смещение до IP заголовка
    struct udphdr *udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);  // Смещение до UDP заголовка
    struct dns_header *dnsh = (struct dns_header *)(packet + 14 + iph->ip_hl * 4 + sizeof(struct udphdr)); 
    
    char time_str[20]; 
    struct tm *ltime = localtime(&header->ts.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);  

    printf("Timestamp: %s\n", time_str);
    printf("SrcIP: %s\n", inet_ntoa(iph->ip_src));
    printf("DstIP: %s\n", inet_ntoa(iph->ip_dst));
    printf("SrcPort: UDP/%d\n", ntohs(udph->uh_sport));
    printf("DstPort: UDP/%d\n", ntohs(udph->uh_dport));
    printf("Identifier: 0x%04X\n", ntohs(dnsh->id));
    printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
        (dnsh->flags >> 15) & 0x1, // QR
        (dnsh->flags >> 11) & 0xF, // OPCODE
        (dnsh->flags >> 10) & 0x1, // AA
        (dnsh->flags >> 9) & 0x1,  // TC
        (dnsh->flags >> 8) & 0x1,  // RD
        (dnsh->flags >> 7) & 0x1,  // RA
        (dnsh->flags >> 5) & 0x1,  // AD
        (dnsh->flags >> 4) & 0x1,  // CD
        dnsh->flags & 0xF           // RCODE
    );

    printf("[Question Section]\n");

    // Здесь будет код для разбора секции Question и вывода её содержимого.
    // Можно создать отдельную функцию для разбора записи.

    printf("====================\n");
}

// Основная функция
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];  
    struct bpf_program fp;
    struct InputData input_data;

    input_data = parse_arguments(argc, argv);

    signal(SIGINT, handle_sigint);

    printf("argc: %d\n", argc);
    printf("-i: %s\n-p: %s\n-v: %s\n-d: %s\n-t: %s\n", input_data.interface, input_data.pcapfile, 
                                                        (input_data.verbose ? "true" : "false"),
                                                        input_data.domainsfile, input_data.transfile);

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    
    char filter_exp[] = "udp port 53";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);  // 0 означает "бесконечно"

    pcap_close(handle);
    
    printf("Program terminated gracefully.\n");

    return 0;
}
