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
#ifndef HAVE_PHP_TRACE_H
#define HAVE_PHP_TRACE_H

typedef enum _php_trace_action_t {
    PHP_TRACE_OK = 0,
    PHP_TRACE_STOP = 1,
    PHP_TRACE_QUIT = 2,
} php_trace_action_t;

typedef struct _php_trace_context_t php_trace_context_t;

struct _php_trace_context_t {
    pid_t     pid;
    zend_long max;
    zend_long depth;
    zend_long freq;
    
    zend_bool attached;
    zend_long samples;
    HashTable symbols;
    HashTable functions;
    HashTable classes;

    void               (*onBegin)(struct _php_trace_context_t*);
    php_trace_action_t (*onAttach)(struct _php_trace_context_t*);
    php_trace_action_t (*onStackStart)(struct _php_trace_context_t*);
    php_trace_action_t (*onFrame)(struct _php_trace_context_t*, 
                                    zend_execute_data *frame, 
                                    uint32_t depth, 
                                    zend_function *function, 
                                    zend_op *instruction);
    php_trace_action_t (*onStackFinish)(struct _php_trace_context_t*);
    php_trace_action_t (*onDetach)(struct _php_trace_context_t*);
    void               (*onEnd)(struct _php_trace_context_t*);
};

PHPAPI php_trace_action_t php_trace_frame_print(
        php_trace_context_t *context, 
        zend_execute_data *frame, 
        uint32_t depth, 
        zend_function *function, 
        zend_op *instruction);

PHPAPI php_trace_context_t php_trace_context = {
    .max   = -1,
    .depth = 64,
    .freq  = 1000,

    .onBegin       = NULL,
    .onAttach      = NULL,
    .onStackStart  = NULL,
    .onFrame       = php_trace_frame_print,
    .onStackFinish = NULL,
    .onDetach      = NULL,
    .onEnd         = NULL
};
#endif

