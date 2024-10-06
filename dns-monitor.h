#ifndef DNS_MONITOR
#define DNS_MONITOR

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <signal.h>

struct InputData{
    char* interface;
    char* pcapfile;
    int verbose;
    char* domainsfile;
    char* transfile;
};


#endif