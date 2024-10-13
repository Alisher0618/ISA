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

    printf("[Question Section]\n");

    // Здесь будет код для разбора секции Question и вывода её содержимого.
    // Можно создать отдельную функцию для разбора записи.

    printf("====================\n");
}

pcap_t *handle_interface(char *interface){
    char errbuf[PCAP_ERRBUF_SIZE];  
    pcap_t *handle = NULL;
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
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

pcap_t *handle_pcap_file(char* pcapfile){
    char errbuf[PCAP_ERRBUF_SIZE];  
    pcap_t *handle = NULL;
    handle = pcap_open_offline(pcapfile, errbuf);
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
        handle = handle_interface(input_data.interface);
    }else{
        printf("pcap file: %s\n", input_data.pcapfile);//delete
        printf("=========\n");//delete
        handle = handle_pcap_file(input_data.pcapfile);
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
    struct InputData input_data;

    input_data = parse_arguments(argc, argv);

    //signal(SIGINT, handle_sigint);

    printf("argc: %d\n", argc);
    
    start_monitoring(input_data);

    

    return 0;
}
