/**
* @file dns-monitor.c
* @brief Impelementation of DNS communication
*
* @author Alisher Mazhirinov (xmazhi00)
*
*/
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

#define SKIP_IF_ETHERNET 42
#define SKIP_IF_SLL 44
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

int in_offline = 0;
int allowed_types[7] = {1, 2, 5, 6, 15, 28, 33};
int num_of_info = 0;
int write_domains;
int write_translations;
int jump_to_dns;

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
const uint8_t *receive_domain(const uint8_t *packet, const uint8_t *reader, char *domain_name) {
    int p = 0;  
    jumped = 0;
    const uint8_t *orig_reader = reader;
    int offset;
    int one_jump = 1;
    while (*reader != 0) {
        if ((*reader & 0xC0) == 0xC0){ 
            if(one_jump){
                orig_reader = reader;
                one_jump = 0;
            }
            offset = (*reader & 0x3F) << 8 | *(reader + 1);
            reader = packet + offset; 
            jumped = 1;       
        } else {
            for (int i = 0; i < *reader; i++) {
                domain_name[p++] = *(reader + 1 + i);
            }
            domain_name[p++] = '.';

            reader += *reader + 1; 
        }
    }   
    domain_name[p] = '\0';

    if (jumped) {
        return orig_reader + 2;
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
        receive_domain(packet + jump_to_dns, rdata, ns_domain_name);

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
        mx_data = receive_domain(packet + jump_to_dns, mx_data, mx_domain_name);
        printf("%u %s\n", mx_priority, mx_domain_name);
    }
    else if (type == 5 && length > 0) { // CNAME record
        char cname_domain_name[SIZE];
        const uint8_t *cname_data = rdata;
        cname_data = receive_domain(packet + jump_to_dns, cname_data, cname_domain_name);
        printf("%s\n", cname_domain_name);  
    }
    else if (type == 6) { // SOA record
        char mname[SIZE], rname[SIZE];
        const uint8_t *vdata = rdata; 
        vdata = receive_domain(packet + jump_to_dns, vdata, mname); // Primary NS
        if(jumped){
            vdata = receive_domain(packet + jump_to_dns, vdata, rname); // Responsible authority's mailbox
            jumped = 0;
        }else{
            vdata = receive_domain(packet + jump_to_dns, vdata, rname); // Responsible authority's mailbox
        }

        vdata += 4; //skipping serial
        vdata += 4; //skipping refresh
        vdata += 4; //skipping retry
        vdata += 4; //skipping expire
        vdata += 4; //skipping minimum

        if(write_domains){
            fclose(file_domains);
            file_domains = fopen(input_data.domainsfile, "r");

            write_to_domain(mname);
        }

        printf("%s %s\n", mname, rname);
    }else if (type == 33) { // SRV record
        const uint8_t *adata = rdata;
        adata += 2; //skipping priority
        adata += 2; //skipping weight
        adata += 2; // skipping port
        
        char srv_domain_name[SIZE];
        adata = receive_domain(packet + jump_to_dns, adata, srv_domain_name);

        printf("%s\n", srv_domain_name);
    }
}

const uint8_t *sections_handle(int number, const uint8_t *packet, const uint8_t *reader, char *domain_name, char *section){
    int printSection = 1;
    unsigned int ttl;
    unsigned short atype, aclass, rdlength;
    const uint8_t *rdata;
    for (int i = 0; i < number; i++) {
        reader = receive_domain(packet + jump_to_dns, reader, domain_name);        
        atype = ntohs(*(unsigned short *)reader);
        reader += 2;
        aclass = ntohs(*(unsigned short *)reader);
        reader += 2;

        if(strcmp(section, "ques") != 0){
            ttl = ntohl(*(unsigned int *)reader);
            reader += 4;
            rdlength = ntohs(*(unsigned short *)reader);
            reader += 2;

            rdata = reader;
            reader += rdlength; 
        }
       
        if(isAllowedType(atype)){
            if(printSection){
                if(strcmp(section, "ques") == 0){
                    printf("\n[Question Section]\n");
                }else if(strcmp(section, "answ") == 0){
                    printf("\n[Answer Section]\n");
                }else if(strcmp(section, "auth") == 0){
                    printf("\n[Authority Section]\n");
                }else{
                    printf("\n[Additional Section]\n");
                }
                
                printSection = 0;
            }

            if(write_domains){
                fclose(file_domains);
                file_domains = fopen(input_data.domainsfile, "r");

                write_to_domain(domain_name);
            }
            
            printf("%s ", domain_name);

            if(strcmp(section, "ques") != 0){
                printf("%u ", ttl);
            }
            
            if(aclass == 1){
                printf("IN ");
            }

            if(atype == 1){
                printf("A");
            }else if(atype == 2){
                printf("NS");
            }else if(atype == 5){
                printf("CNAME");
            }else if(atype == 6){
                printf("SOA");
            }else if(atype == 15){
                printf("MX");
            }else if(atype == 28){
                printf("AAAA");
            }else if(atype == 33){
                printf("SRV");
            }

            if(strcmp(section, "ques") != 0){
                printf(" ");
                print_domains(atype, rdlength, rdata, packet, domain_name);
            }else{
                printf("\n");
            }
    
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
    struct ip *ipv4_h;
    struct ip6_hdr *ipv6_h;
    struct udphdr *udp_h;
    struct dns_header *dns_h;
    const uint8_t *ip_header;

    (void) args;
    (void) header;

    int ip_version = 0; // 0 - ipv4, 1 - ipv6
    int interface_type = 0; // 0 - ethernet, 1 - sll
    int dlt = pcap_datalink(handle);
    if(dlt == DLT_EN10MB){ // Ethernet
        jump_to_dns = SKIP_IF_ETHERNET;
        interface_type = 0;
        ip_header = packet + 14;
    }else if(dlt == DLT_LINUX_SLL){ // Linux cooked
        jump_to_dns = SKIP_IF_SLL;
        interface_type = 1;
        ip_header = packet + 16;
    }else{
        fprintf(stderr, "Unsupported type\n");
        exit(EXIT_FAILURE);
    }


    char time_str[20]; 
    struct tm *ltime = localtime(&header->ts.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ltime);  

    // UDP header is after IP header
    const uint8_t *udp_header;
    if(ip_header[0] == 0x45){ // IPv4
        if (ip_header[9] != 17) {
            fprintf(stderr, "ERROR: Protocol is not udp\n");
            exit(EXIT_FAILURE);
        }
        int skip_bytes = interface_type == 0 ? 14 : 16;

        ipv4_h = (struct ip *)(packet + skip_bytes);
        udp_h = (struct udphdr *)(packet + skip_bytes + ipv4_h->ip_hl * 4);
        dns_h = (struct dns_header *)(packet + skip_bytes + ipv4_h->ip_hl * 4 + sizeof(struct udphdr)); 

        udp_header = ip_header + 20;
        ip_version = 0;

        unsigned short src_port = ntohs(*(unsigned short * )(udp_header));
        unsigned short dst_port = ntohs(*(unsigned short * )(udp_header + 2));
        
        if (src_port != 53 && dst_port != 53) {
            fprintf(stderr, "ERROR: It is not UDP package\n");
            exit(EXIT_FAILURE);
        }

    }
    else if((ip_header[0] & 0xF0) == 0x60){
        if (ip_header[6] != 17) {
            fprintf(stderr, "ERROR: Protocol is not UDP\n");
            exit(EXIT_FAILURE);
        }
        jump_to_dns += 20; // add another 20 bytes
        int skip_bytes = interface_type == 0 ? 14 : 16;

        ipv6_h = (struct ip6_hdr *)(packet + skip_bytes);
        udp_h = (struct udphdr *)(packet + skip_bytes + sizeof(struct ip6_hdr));
        dns_h = (struct dns_header *)(packet + skip_bytes + sizeof(struct ip6_hdr) + sizeof(struct udphdr));

        udp_header = ip_header + 40;
        ip_version = 1;

        if (ntohs(udp_h->uh_sport) != 53 && ntohs(udp_h->uh_dport) != 53) {
            fprintf(stderr, "ERROR: It is not udp package\n");
            exit(EXIT_FAILURE);
        }
    }else{
        fprintf(stderr, "Unknown IP version\n");
        exit(EXIT_FAILURE);
    }

    // DNS header starts after UDP header in 8 bytes
    const uint8_t *dns_header_data = udp_header + 8;
    struct dns_header *dns = (struct dns_header *)dns_header_data;
    

    if(!input_data.verbose){
        printf("%s ", time_str);
        if(ip_version == 0){
            printf("%s ", inet_ntoa(ipv4_h->ip_src));
            printf("-> ");
            printf("%s ", inet_ntoa(ipv4_h->ip_dst));
        }else{
            char src_addr[INET6_ADDRSTRLEN], dst_addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6_h->ip6_src), src_addr, sizeof(src_addr));
            inet_ntop(AF_INET6, &(ipv6_h->ip6_dst), dst_addr, sizeof(dst_addr));

            printf("%s ", src_addr);
            printf("-> ");
            printf("%s ", dst_addr);
        }
        

        if(((ntohs(dns_h->flags) >> 15) & 0x1) == 0){
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
            printf("Timestamp: %s\n", time_str);
            printf("SrcIP: %s\n", inet_ntoa(ipv4_h->ip_src));
            printf("DstIP: %s\n", inet_ntoa(ipv4_h->ip_dst));
            printf("SrcPort: UDP/%d\n", ntohs(udp_h->uh_sport));
            printf("DstPort: UDP/%d\n", ntohs(udp_h->uh_dport));
            printf("Identifier: 0x%04X\n", ntohs(dns_h->id));
        }else{
            char src_addr[INET6_ADDRSTRLEN], dst_addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6_h->ip6_src), src_addr, sizeof(src_addr));
            inet_ntop(AF_INET6, &(ipv6_h->ip6_dst), dst_addr, sizeof(dst_addr));

            printf("Timestamp: %s\n", time_str);
            printf("SrcIP: %s\n", src_addr);
            printf("DstIP: %s\n", dst_addr);
            printf("SrcPort: UDP/%d\n", ntohs(udp_h->uh_sport));
            printf("DstPort: UDP/%d\n", ntohs(udp_h->uh_dport));
            printf("Identifier: 0x%04X\n", ntohs(dns_h->id));
        }
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
            (ntohs(dns_h->flags) >> 15) & 0x1, // QR
            (ntohs(dns_h->flags) >> 11) & 0xF, // OPCODE
            (ntohs(dns_h->flags) >> 10) & 0x1, // AA
            (ntohs(dns_h->flags) >> 9) & 0x1,  // TC
            (ntohs(dns_h->flags) >> 8) & 0x1,  // RD
            (ntohs(dns_h->flags) >> 7) & 0x1,  // RA
            (ntohs(dns_h->flags) >> 5) & 0x1,  // AD
            (ntohs(dns_h->flags) >> 4) & 0x1,  // CD
            ntohs(dns_h->flags) & 0xF           // RCODE
        );

        const uint8_t *reader = dns_header_data + 12;  // Jump to Question section
        char domain_name[SIZE];
        
        // Question Section
        if(ntohs(dns->qdcount) >= 1){
            reader = sections_handle(ntohs(dns->qdcount), packet, reader, domain_name, "ques");
        }

        // Answer Section
        if(ntohs(dns->ancount) >= 1){
            reader = sections_handle(ntohs(dns->ancount), packet, reader, domain_name, "answ");
        }

        // Authority Section
        if(ntohs(dns->nscount) >= 1){
            reader = sections_handle(ntohs(dns->nscount), packet, reader, domain_name, "auth");
        }

        // Additional Section
        if(ntohs(dns->arcount) >= 1){
            reader = sections_handle(ntohs(dns->arcount), packet, reader, domain_name, "addi");
        }

        printf("====================\n");
    }
    
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
