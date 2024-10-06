

#include "parse_args.h"

// ./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]
// max valid number of args: 6
// min valid number of args: 3

struct InputData parse_arguments(int argc, char **argv){
    int opt;
    struct InputData get_values;

    get_values.interface = "none";
    get_values.pcapfile = "none";
    get_values.verbose = 0;
    get_values.domainsfile = "none";
    get_values.transfile = "none";

    if(argc < 3 || argc > 8){
        printf("help\n");
        exit(EXIT_FAILURE);
    }
    else{
        for(int i = 0; i < argc; i++){
            if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0){
                printf("help:)\n");
                exit(0);
            }
            else if(strcmp(argv[i], "-i") == 0){
                get_values.interface = argv[i+1];
            }
            else if(strcmp(argv[i], "-p") == 0){
                get_values.pcapfile = argv[i+1];
            }
            else if (strcmp(argv[i], "-v") == 0){
                get_values.verbose = 1;
            }
            else if (strcmp(argv[i], "-d") == 0){
                get_values.domainsfile = argv[i+1];
            }
            else if (strcmp(argv[i], "-t") == 0){
                get_values.transfile = argv[i+1];
            }
            /*else{
                printf("help:(\n");
                exit(EXIT_FAILURE);
            }*/
        }
    }

    return get_values;
}