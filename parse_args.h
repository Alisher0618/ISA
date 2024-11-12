#ifndef PARSE_ARGS
#define PARSE_ARGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <signal.h>

#include "dns-monitor.h"


/**
 * @brief Function for processing input arguments
 *        Can also write help message
 * 
 * @param argc 
 * @param argv 
 * @return struct InputData 
 */
struct InputData parse_arguments(int args,  char **argv);

#endif