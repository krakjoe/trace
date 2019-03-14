/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | https://php.net/license/3_01.txt                                     |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: krakjoe                                                      |
  +----------------------------------------------------------------------+
*/

#ifndef HAVE_PHP_TRACE_MAIN
#define HAVE_PHP_TRACE_MAIN

#include <php.h>
#include <php_getopt.h>
#include <php_trace.h>

const opt_struct php_trace_options[] = {
    {'p', 1, "process"},
    {'e', 1, "executor"},
    {'m', 1, "max"},
    {'d', 1, "depth"},
    {'f', 1, "frequency"},
    {'s', 0, "stack"},
    {99,  0, "with-array-elements"},
    {199, 0, "with-string-contents"},
    {'h', 0, "help"},
    {'-', 0, NULL}       /* end of args */
};

static void php_trace_usage(char *argv0) {
    char *prog;

	prog = strrchr(argv0, '/');
	if (prog) {
		prog++;
	} else {
		prog = "php-trace";
	}

	fprintf(stderr,
	            "Usage: %s [options] [flags] -p <target>\n"
	            "Options:\n"
				"           -d --executor   <hex> Executor address          (default auto)\n"
				"           -d --depth      <int> Maximum stack depth       (default 64)\n"
				"           -m --max        <int> Maximum stack traces      (default unlimited)\n"
				"           -f --frequency  <int> Frequency of collection   (default 1000)\n"
				"Flags:\n"
				"           -s --stack                             Copy variables on stack from frame\n"
				"              --with-array-elements               Copy array elements\n"
				"              --with-string-contents              Copy string contents\n"
				"Example Usage:\n"
				"%s -p 1337 -d1         - trace process 1337 generating traces with a single frame\n"
				"%s -p 1337 -d128 -m100 - trace process 1337 generating traces 128 frames deep stopping at 100 traces\n"
				, prog, prog, prog);
}

static zend_always_inline zend_executor_globals* php_trace_executor_parse(const char *address) {
    size_t length = strlen(address);
    
    if (length > 2 && address[0] == '0' &&
                      (address[1] == 'x' || address[1] == 'X')) {
    
        return (zend_executor_globals*) strtoul(address + 2, NULL, 16);                  
    }
    
    return (zend_executor_globals*) FAILURE;
}

int main(int argc, char **argv) {
    char *php_trace_optarg = NULL;
    int   php_trace_optind = 1,
          php_trace_optcur = 0;
          
    php_trace_context_t php_trace_context = {
        .max         = -1,
        .depth       = 64,
        .freq        = 1000,
        .stack       = 0,
        .arData      = 0,
        .strData     = 0,
        .interrupted = 0,

        .onBegin       = php_trace_begin,
        .onAttach      = NULL,
        .onStackStart  = php_trace_stack_start,
        .onFrame       = php_trace_print_frame,
        .onStackFinish = php_trace_stack_finish,
        .onDetach      = NULL,
        .onEnd         = NULL,
        
        .onSchedule    = php_trace_schedule
    };
    
    while ((php_trace_optcur = php_getopt(argc, argv, php_trace_options, &php_trace_optarg, &php_trace_optind, 0, 2)) != -1) {
        switch (php_trace_optcur) {
            case 'p': php_trace_context.pid        =  (pid_t) strtol(php_trace_optarg, NULL, 10);                          break;
            case 'e': php_trace_context.executor   =  php_trace_executor_parse(php_trace_optarg);                          break;
            case 'm': php_trace_context.max        =  strtoul(php_trace_optarg, NULL, 10);                                 break;
            case 'd': php_trace_context.depth      =  strtoul(php_trace_optarg, NULL, 10);                                 break;
            case 'f': php_trace_context.freq       =  strtoul(php_trace_optarg, NULL, 10);                                 break;
            case 's': php_trace_context.stack      =  1;                                                                   break;
    
            case 99:  php_trace_context.arData     =  1;                                                                   break;
            case 199: php_trace_context.strData    =  1;                                                                   break;
                                
            case 'h': {
                php_trace_usage(argv[0]);
                return 0;
            } break;
            
            default:
                break;
        }
    }
    
    if (php_trace_context.executor == ((zend_executor_globals*)FAILURE)) {
        fprintf(stderr, 
            "Executor address is not valid:\n");
        php_trace_usage(argv[0]);
        return 1;
    }
    
    if (!php_trace_context.pid) {
        fprintf(stderr, 
            "Target process is required:\n");
        php_trace_usage(argv[0]);
        return 1;
    }
    
    if (php_trace_optind < argc) {
        fprintf(stderr, 
            "Unrecognized argument at %s:\n",    
            argv[php_trace_optind]);
        php_trace_usage(argv[0]);
        return 1;
    }

    /* TODO strip parsed args from argc/argv */
    return php_trace_loop(&php_trace_context, argc, argv);
}
#endif
