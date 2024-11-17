/**
* @file parse_args.c
* @brief Parsing input arguments
*
* @author Alisher Mazhirinov (xmazhi00)
*
*/
#include "parse_args.h"

// ./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]
// sudo ./dns-monitor -i eth0 -v -d text.txt -t text1.txt
// sudo ./dns-monitor -p test.pcapng -v -d text.txt -t text1.txt

/**
 * @brief Function for printing useful information
 */
void printHelp(){
    printf("==============================DNS-MONITOR APPLICATION=============================\n\n");
    printf("-i -- The name of the interface on which the program will listen.\n");
    printf("-p -- The name of the PCAP file that the program will process.   \n");
    printf("-v -- Verbose mode: full listing of DNS message details.       \n");
    printf("-d -- The name of the domain name file.\n");
    printf("-t -- The name of the domain name to IP translation file.\n\n");
    printf("==============================DNS-MONITOR APPLICATION=============================\n");
}

/**
 * @brief Function for processing input arguments
 *        Can also write help message
 * 
 * @param argc 
 * @param argv 
 * @return struct InputData 
 */
struct InputData parse_arguments(int argc, char **argv){
    int opt;
    struct InputData get_values;

    get_values.interface = "none";
    get_values.pcapfile = "none";
    get_values.verbose = 0;
    get_values.domainsfile = NULL;
    get_values.transfile = NULL;

    if(argc < 3 || argc > 8){
        printHelp();
        exit(EXIT_FAILURE);
    }
    else{

        // Parse command line arguments
        while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
            switch (opt) {
            case 'i':
                get_values.interface = optarg;
                break;

            case 'p':
                get_values.pcapfile = optarg;
                break;
            
            case 'v':
                get_values.verbose = 1;
                break;

            case 'd':
                if (optind-1 < argc && argv[optind-1][0] != '-') {
                    get_values.domainsfile = argv[optind-1];
                } else {
                    fprintf(stderr, "Error: Option -d requires a file argument\n");
                    printHelp();
                    exit(EXIT_FAILURE);
                }
                break;
            
            case 't':
                get_values.transfile = optarg;
                break;
            
            case '?':
                printHelp();
                exit(EXIT_FAILURE);
 
            }
        
        }

        if (strcmp(get_values.pcapfile, "none") == 0 && strcmp(get_values.interface, "none") == 0){
            printf("ERROR: Expected either pcapfile or interface\n");
            printf("Printing help message...\n");
            printHelp();
            exit(EXIT_FAILURE);
            
        }
        
        if(strcmp(get_values.pcapfile, "none") != 0 && strcmp(get_values.interface, "none") != 0){
            printf("ERROR: Expected at least pcapfile or interface\n");
            printf("Printing help message...\n");
            printHelp();
            exit(EXIT_FAILURE);
        }

    }

    return get_values;
}