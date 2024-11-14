#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <pcap.h>   
#include <arpa/nameser.h>
#include <netinet/ip6.h>
#include <resolv.h>
#include "parse_args.h"

#define ETHERTYPE_IP 0x0800
#define SKIP_IF_ETHERNET 42
#define SKIP_IF_SLL 44
#define DNS_HEADER_SIZE 12
#define SLL 0x8000
#define SIZE 256

// DNS Header Structure
struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount; // number of questions
    unsigned short ancount; // number of answers
    unsigned short nscount; // number of authorities
    unsigned short arcount; // number of additional
};

FILE *file_domains, *file_translations;
struct InputData input_data;
pcap_t *handle;           
struct bpf_program fp;

volatile int running = 1; 
int in_offline = 0;
int allowed_types[7] = {1, 2, 5, 6, 15, 28, 33};
int num_of_info = 0;
int write_domains;
int write_translations;
int jump_to_dns;

int unsupported_type = 0;

/**
 * @brief Function to gracefully terminate program if a certain signal has been received
 * 
 * @param signal 
 */
void terminate_program(int signal){
    if (signal == SIGINT || signal == SIGTERM || signal == SIGQUIT){
        pcap_breakloop(handle); 
        pcap_close(handle);
    }else if (in_offline) {
        //print_traffic_offline();
        pcap_close(handle);
    }else{
        pcap_close(handle);
    }
    pcap_freecode(&fp);

    if (write_domains){
        fclose(file_domains);
    }
    
    if (write_translations){
        fclose(file_translations);
    }

    exit(EXIT_SUCCESS);
}

/**
 * @brief Function for checking if domain name is already written to file
 *        to avoid duplicates
 * 
 * @param domain 
 * @return int 
 */
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

/**
 * @brief Function for checking if translation of domain name is already written to file
 *        to avoid duplicates
 * 
 * @param domain 
 * @param ip_address 
 * @return int 
 */
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

/**
 * @brief Function for writing unique domain names to file
 * 
 * @param domain_name 
 */
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

/**
 * @brief Function for writing unique translation of domain name to file
 * 
 * @param domain_name 
 * @param ip_address 
 */
void write_to_translation(char *domain_name, char* ip_address){
    char row[SIZE];
    strcpy(row, domain_name);
    row[strlen(row)-1] = '\0';
    
    if(!translation_exists(row, ip_address)){
        fclose(file_translations);   //closing for reading
        file_translations = fopen(input_data.transfile, "a");
        
        fprintf(file_translations, "%s\n", row);
        
        fclose(file_translations);   //closing for adding
        file_translations = fopen(input_data.transfile, "r");
    }
}

/**
 * @brief Function that checks if type of record is supported
 * 
 * @param checkType 
 * @return int 
 */
int isAllowedType(int checkType){
    for (int i = 0; i < 7; i++){
        if(checkType == allowed_types[i]){
            return 1;
        }
    }
    
    return 0;
}

int jumped;  
int is_soa;
/**
 * @brief Function for processing domain names in DNS part of the whole package
 *        It allows to receive domain names by reading them and saving to domain_name variable
 *        And also can can process compression pointer
 * 
 * @param packet 
 * @param reader 
 * @param domain_name 
 * @return const uint8_t* 
 */
const uint8_t *extract_domain_name(const uint8_t *packet, const uint8_t *reader, char *domain_name) {
    int p = 0;  
    jumped = 0;
    const uint8_t *orig_reader = reader;
    const uint8_t *tmp_reader = reader;
    char next[SIZE] = {0};
    int offset, off_1, off_2; 
    int step = 0;
    int was_in_else = 0;

    int num = 0;
    //printf("\n%02x %02x %02x %02x\n", reader[0], reader[1], reader[2], reader[3]);
    while (*reader != 0) {
        if ((*reader & 0xC0) == 0xC0){ 
            num++;
            //tmp_reader = reader;
            if(is_soa || was_in_else){
                //printf("here\n");
                orig_reader = reader;
                //was_in_else = 0;
            }
            off_1 = (*reader & 0x3F) << 8;
            
            offset = (*reader & 0x3F) << 8 | *(reader + 1);
            //printf("OFF_1: %d\n", offset);
            reader = packet + offset; 
            jumped = 1;
            
        } else {
            was_in_else = 1;
            for (int i = 0; i < *reader; i++) {
                next[step++] = *(reader + 1 + i);
                domain_name[p++] = *(reader + 1 + i);
            }
            next[step++] = '.';  
            domain_name[p++] = '.';

            reader += *reader + 1; 
        }
    }   

    domain_name[p] = '\0';

    if (jumped) {
        if (num == 1) {
            //printf("\n%02x %02x %02x %02x %d\n", orig_reader[0 - 1], orig_reader[1], orig_reader[2], orig_reader[3], was_in_else);
            return orig_reader + 2;
        }else{
            return tmp_reader + 2;
        }
    }

    return reader + 1;
}

/**
 * @brief Function for printing information about different DNS records
 * 
 * @param type 
 * @param length 
 * @param rdata 
 * @param packet 
 * @param domain_name 
 */
void print_domains(unsigned short type, unsigned short length, const uint8_t *rdata, const uint8_t *packet, char *domain_name){
    if (type == 1) { // A record (IPv4)
        struct in_addr addr;
        memcpy(&addr, rdata, sizeof(struct in_addr));
        printf("%s\n", inet_ntoa(addr));
        if(write_translations){
            fclose(file_translations);
            file_translations = fopen(input_data.transfile, "r");

            write_to_translation(domain_name, inet_ntoa(addr));  
        }
    }
    else if (type == 2 && length > 0) { // NS record
        char ns_domain_name[SIZE];
        extract_domain_name(packet + jump_to_dns, rdata, ns_domain_name);

        if(write_domains){
            fclose(file_domains);
            file_domains = fopen(input_data.domainsfile, "r");

            write_to_domain(ns_domain_name);
        }
        printf("%s\n", ns_domain_name);
    }
    else if (type == 28) { // AAAA record (IPv6)
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
    else if (type == 15 && length > 0) { // MX record
        unsigned short mx_priority;
        memcpy(&mx_priority, rdata, sizeof(unsigned short));
        mx_priority = ntohs(mx_priority); 
        const uint8_t *mx_data = rdata + 2; 

        char mx_domain_name[SIZE];
        mx_data = extract_domain_name(packet + jump_to_dns, mx_data, mx_domain_name);
        printf("%u %s\n", mx_priority, mx_domain_name);
    }
    else if (type == 5 && length > 0) { // CNAME record
        char cname_domain_name[SIZE];
        const uint8_t *cname_data = rdata;
        cname_data = extract_domain_name(packet + jump_to_dns, cname_data, cname_domain_name);
        printf("%s\n", cname_domain_name);  
    }
    else if (type == 6) { // SOA record
        char mname[SIZE], rname[SIZE];
        const uint8_t *vdata = rdata; 
        is_soa = 1;
        vdata = extract_domain_name(packet + jump_to_dns, vdata, mname); // Primary NS
        if(jumped){
            vdata = extract_domain_name(packet + jump_to_dns, vdata, rname); // Responsible authority's mailbox
            jumped = 0;
        }else{
            vdata = extract_domain_name(packet + jump_to_dns, vdata, rname); // Responsible authority's mailbox
        }
        is_soa = 0;

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
    }else if (type == 33) { // SRV record
        const uint8_t *adata = rdata;
        unsigned short priority = ntohs(*(unsigned short *)adata); adata += 2;
        unsigned short weight = ntohs(*(unsigned short *)adata); adata += 2;
        unsigned short port = ntohs(*(unsigned short *)adata); adata += 2;
        
        char srv_domain_name[SIZE];
        adata = extract_domain_name(packet + jump_to_dns, adata, srv_domain_name);

        printf("%s\n", srv_domain_name);
    }
}

/**
 * @brief Function for processing answer section of DNS package
 * 
 * @param number 
 * @param packet 
 * @param reader 
 * @param domain_name 
 * @return const uint8_t* 
 */
const uint8_t *question_section(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name){
    int printSection = 1;
    for (int i = 0; i < number; i++) {
        reader = extract_domain_name(packet, reader, domain_name);
        unsigned short qtype = ntohs(*(unsigned short *)reader);
        reader += 2;
        unsigned short qclass = ntohs(*(unsigned short *)reader);
        reader += 2; 

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
        }else{
            //printf("here\n");
            unsupported_type = 0;
        }
    }

    return reader;
}

/**
 * @brief Function for processing answer section of DNS package
 * 
 * @param number 
 * @param packet 
 * @param reader 
 * @param domain_name 
 * @return const uint8_t* 
 */
const uint8_t *answer_section(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name){
    int printSection = 1;
    for (int i = 0; i < number; i++) {
        //printf("%d\n", jump_to_dns);
        //printf("\n%02x %02x %02x %02x\n", (packet + jump_to_dns)[0], (packet + jump_to_dns)[1], (packet + jump_to_dns)[2], (packet + jump_to_dns)[3]);
        reader = extract_domain_name(packet + jump_to_dns, reader, domain_name);
        //printf("domain: %s\n", domain_name);
        unsigned short atype = ntohs(*(unsigned short *)reader);
        //printf("atype: %d\n", atype);
        reader += 2;
        unsigned short aclass = ntohs(*(unsigned short *)reader);
        reader += 2; 
        unsigned int ttl = ntohl(*(unsigned int *)reader);
        reader += 4; 
        unsigned short rdlength = ntohs(*(unsigned short *)reader);
        reader += 2;

        const uint8_t *rdata = reader; 
        
        reader += rdlength;
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

    }
    return reader;

}

/**
 * @brief Function for processing authority section of DNS package
 * 
 * @param number 
 * @param packet 
 * @param reader 
 * @param domain_name 
 * @return const uint8_t* 
 */
const uint8_t *authority_section(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name){
    int printSection = 1;
    for (int i = 0; i < number; i++) {
        reader = extract_domain_name(packet + jump_to_dns, reader, domain_name);

        unsigned short atype = ntohs(*(unsigned short *)reader);
        reader += 2; 
        unsigned short aclass = ntohs(*(unsigned short *)reader);
        reader += 2;
        unsigned int ttl = ntohl(*(unsigned int *)reader);
        reader += 4; 
        unsigned short rdlength = ntohs(*(unsigned short *)reader);
        reader += 2; 

        const uint8_t *rdata = reader;
        reader += rdlength;
        
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
 
    }

    return reader;
}

/**
 * @brief Function for processing additional section of DNS package
 * 
 * @param number
 * @param packet 
 * @param reader 
 * @param domain_name 
 * @return const uint8_t* 
 */
const uint8_t *additional_section(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name){
    int printSection = 1;
    for (int i = 0; i < number; i++) {
        //printf("\n%02x %02x %02x %02x\n", (packet + jump_to_dns)[0], (packet + jump_to_dns)[1], (packet + jump_to_dns)[2], (packet + jump_to_dns)[3]);
        //printf("\n%02x %02x %02x %02x\n", reader[0], reader[1], reader[2], reader[3]);
        reader = extract_domain_name(packet + jump_to_dns, reader, domain_name);        
        unsigned short atype = ntohs(*(unsigned short *)reader);
        reader += 2;
        unsigned short aclass = ntohs(*(unsigned short *)reader);
        reader += 2;
        unsigned int ttl = ntohl(*(unsigned int *)reader);
        reader += 4;
        unsigned short rdlength = ntohs(*(unsigned short *)reader);
        reader += 2;

        const uint8_t *rdata = reader;
        reader += rdlength;
        //printf("atype: %d\n", atype);
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

    }

    return reader;
}

/**
 * @brief Function that handles all incoming DNS packages
 * 
 * @param args
 * @param header 
 * @param packet 
 */
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

    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct udphdr *udph;
    struct dns_header *dnsh;
    const uint8_t *ip_header;

    int ip_version = 0; // 0 - ipv4, 1 - ipv6
    int interface_type = 0; // 0 - ethernet, 1 - sll
    int dlt = pcap_datalink(handle);
    if(dlt == DLT_EN10MB){ // Ethernet
        jump_to_dns = SKIP_IF_ETHERNET;
        interface_type = 0;
        //iph = (struct ip *)(packet + 14);  // Jump to IP header
        //udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);  // Jump to UDP header
        //dnsh = (struct dns_header *)(packet + 14 + iph->ip_hl * 4 + sizeof(struct udphdr)); 
        ip_header = packet + 14;
    }else if(dlt == DLT_LINUX_SLL){ // Linux cooked
        jump_to_dns = SKIP_IF_SLL;
        interface_type = 1;
        //iph = (struct ip *)(packet + 16);  // Jump to IP header
        //udph = (struct udphdr *)(packet + 16 + iph->ip_hl * 4);  // Jump to UDP header
        //dnsh = (struct dns_header *)(packet + 16 + iph->ip_hl * 4 + sizeof(struct udphdr)); 
        ip_header = packet + 16;
    }

    char time_str[20]; 
    struct tm *ltime = localtime(&header->ts.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);  

    // UDP header is after IP header
    const uint8_t *udp_header;
    if(ip_header[0] == 0x45){ // IPv4
        if (ip_header[9] != 17) { // 17 - это номер для UDP
            fprintf(stderr, "ERROR: Protocol is not udp\n");
            exit(EXIT_FAILURE);
        }
        int skip_bytes = interface_type == 0 ? 14 : 16;

        iph = (struct ip *)(packet + skip_bytes);
        udph = (struct udphdr *)(packet + skip_bytes + iph->ip_hl * 4);  // Jump to UDP header
        dnsh = (struct dns_header *)(packet + skip_bytes + iph->ip_hl * 4 + sizeof(struct udphdr)); 

        udp_header = ip_header + 20;
        ip_version = 0;

        unsigned short src_port = ntohs(*(unsigned short * )(udp_header));
        unsigned short dst_port = ntohs(*(unsigned short * )(udp_header + 2));
        
        if (src_port != 53 && dst_port != 53) {
            fprintf(stderr, "ERROR: It is not udp package\n");
            exit(EXIT_FAILURE);
        }

    }
    else if((ip_header[0] & 0xF0) == 0x60){
        //printf("ipv6 +40\n");
        if (ip_header[6] != 17) { // 17 - это номер для UDP
            fprintf(stderr, "ERROR: Protocol is not udp\n");
            exit(EXIT_FAILURE);
        }
        jump_to_dns += 20; // add another 20 bytes
        int skip_bytes = interface_type == 0 ? 14 : 16;

        ip6h = (struct ip6_hdr *)(packet + skip_bytes);
        udph = (struct udphdr *)(packet + skip_bytes + sizeof(struct ip6_hdr));
        dnsh = (struct dns_header *)(packet + skip_bytes + sizeof(struct ip6_hdr) + sizeof(struct udphdr));

        udp_header = ip_header + 40;
        ip_version = 1;
        //printf("AAAAAAAAAAAAAAAAAAAAAAA: %d, %d\n", ntohs(udph->uh_sport), ntohs(udph->uh_dport));
        if (ntohs(udph->uh_sport) != 53 && ntohs(udph->uh_dport) != 53) {
            fprintf(stderr, "ERROR: It is not udp package\n");
            exit(EXIT_FAILURE);
        }
    }else{
        fprintf(stderr, "Unknown IP version\n");
        exit(EXIT_FAILURE);
    }

    // Gettings src and dst ports
    /*unsigned short src_port = ntohs(*(unsigned short * )(udp_header));
    unsigned short dst_port = ntohs(*(unsigned short * )(udp_header + 2));

    if (src_port != 53 && dst_port != 53) {
        fprintf(stderr, "ERROR: It is not udp package\n");
        exit(EXIT_FAILURE);
    }*/

    // DNS header starts after UDP header in 8 bytes
    const uint8_t *dns_header_data = udp_header + 8;
    struct dns_header *dns = (struct dns_header *)dns_header_data;
    

    if(!input_data.verbose){
        printf("%s ", time_str);
        printf("%s ", inet_ntoa(iph->ip_src));
        printf("-> ");
        printf("%s ", inet_ntoa(iph->ip_dst));

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
        if(ip_version == 0){
            // Вывод информации об IPv4-пакете

            printf("Timestamp: %s\n", time_str);
            printf("SrcIP: %s\n", inet_ntoa(iph->ip_src));
            printf("DstIP: %s\n", inet_ntoa(iph->ip_dst));
            printf("SrcPort: UDP/%d\n", ntohs(udph->uh_sport));
            printf("DstPort: UDP/%d\n", ntohs(udph->uh_dport));
            printf("Identifier: 0x%04X\n", ntohs(dnsh->id));
        }else{
            char src_addr[INET6_ADDRSTRLEN], dst_addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6h->ip6_src), src_addr, sizeof(src_addr));
            inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst_addr, sizeof(dst_addr));

            printf("Timestamp: %s\n", time_str);
            printf("SrcIP: %s\n", src_addr);
            printf("DstIP: %s\n", dst_addr);
            printf("SrcPort: UDP/%d\n", ntohs(udph->uh_sport));
            printf("DstPort: UDP/%d\n", ntohs(udph->uh_dport));
            printf("Identifier: 0x%04X\n", ntohs(dnsh->id));
        }
        /*printf("Timestamp: %s\n", time_str);
        printf("SrcIP: %s\n", inet_ntoa(iph->ip_src));
        printf("DstIP: %s\n", inet_ntoa(iph->ip_dst));
        printf("SrcPort: UDP/%d\n", ntohs(udph->uh_sport));
        printf("DstPort: UDP/%d\n", ntohs(udph->uh_dport));
        printf("Identifier: 0x%04X\n", ntohs(dnsh->id));*/
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

        const uint8_t *reader = dns_header_data + 12;  // Jump to Question section
        char domain_name[SIZE];
        
        // Question Section
        //printf("unsupported: %d\n", unsupported_type);
        if(ntohs(dns->qdcount) >= 1){
            reader = question_section(ntohs(dns->qdcount), packet, reader, domain_name);
        }
        
        // Answer Section
        //printf("unsupported: %d\n", unsupported_type);
        if(ntohs(dns->ancount) >= 1 && unsupported_type == 0){
            reader = answer_section(ntohs(dns->ancount), packet, reader, domain_name);
        }

        // Authority Section
        //printf("unsupported: %d\n", unsupported_type);
        if(ntohs(dns->nscount) >= 1 && unsupported_type == 0){
            reader = authority_section(ntohs(dns->nscount), packet, reader, domain_name);
        }

        // Additional Section
        //printf("unsupported: %d, count: %d\n", unsupported_type, ntohs(dns->arcount));
        if(ntohs(dns->arcount) >= 1 && unsupported_type == 0){
            //printf("aaa\n");
            reader = additional_section(ntohs(dns->arcount), packet, reader, domain_name);
        }

        
        //memset(domain_name, 0, sizeof(domain_name));
    }
    unsupported_type = 0;
    printf("====================\n");
}

/**
 * @brief Function for handling interfaces
 * 
 * @param input_data Structure that contains interface
 * @return pcap_t strcture
 */
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
/**
 * @brief Function for handling pcap file
 * 
 * @param input_data Structure that contains interface
 * @return pcap_t structure
 */
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

/**
 * @brief Function for starting monitoring
 * 
 * @param input_data 
 */
void start_monitoring(struct InputData input_data){
    signal(SIGINT, terminate_program);
    signal(SIGTERM, terminate_program);
    signal(SIGQUIT, terminate_program);
    if(strcmp(input_data.interface, "none") != 0){
        handle = handle_interface(input_data);
    }else{
        handle = handle_pcap_file(input_data);
    }

    if(input_data.domainsfile != NULL){
        write_domains = 1;
        file_domains = fopen(input_data.domainsfile, "w");
    
        if (file_domains == NULL) {
             fprintf(stderr, "Error while opening file\n");
            exit(EXIT_FAILURE);
        }    
    }

    if(input_data.transfile != NULL){
        write_translations = 1;
        file_translations = fopen(input_data.transfile, "w");
    
        if (file_translations == NULL) {
             fprintf(stderr, "Error while opening file\n");
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
    
    start_monitoring(input_data);

    return 0;
}
