#include "parse_args.h"
#include "dns-monitor.h" 

int main(int argc, char *argv[]){
    struct InputData input_data;

    input_data = parse_arguments(argc, argv);

    printf("argc: %d\n", argc);
    printf("-i: %s\n-p: %s\n-v: %s\n-d: %s\n-t: %s\n", input_data.interface, input_data.pcapfile, 
                                                        (input_data.verbose ? "true" : "false"),
                                                        input_data.domainsfile, input_data.transfile);
    
    return 0;
}