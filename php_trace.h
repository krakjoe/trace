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

#include <php.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <signal.h>

typedef enum _php_trace_action_result_t {
    PHP_TRACE_OK = 0,
    PHP_TRACE_STOP = 1,
    PHP_TRACE_QUIT = 2,
} php_trace_action_result_t;

typedef struct _php_trace_context_t php_trace_context_t;

struct _php_trace_context_t {
    pid_t     pid;
    zend_long max;
    zend_long depth;
    zend_long freq;
    zend_bool stack;
    zend_bool arData;
    zend_bool strData;
    zend_bool interrupted;
    
    zend_bool attached;
    zend_long samples;
    HashTable functions;
    HashTable classes;
    HashTable objects;

    void* executor;

    php_trace_action_result_t (*onBegin)(struct _php_trace_context_t*, int argc, char **argv);
    php_trace_action_result_t (*onAttach)(struct _php_trace_context_t*);
    php_trace_action_result_t (*onStackStart)(struct _php_trace_context_t*);
    php_trace_action_result_t (*onFrame)(struct _php_trace_context_t*, zend_execute_data *, zend_long);
    php_trace_action_result_t (*onStackFinish)(struct _php_trace_context_t*);
    php_trace_action_result_t (*onDetach)(struct _php_trace_context_t*);
    void                      (*onEnd)(struct _php_trace_context_t*);
    
    php_trace_action_result_t (*onSchedule)(struct _php_trace_context_t*);
    
    /*
     Reserved for non default context use
    */
    void* ctx;
};

/* {{{ Process Control */
PHPAPI int php_trace_attach(php_trace_context_t *context);
PHPAPI int php_trace_detach(php_trace_context_t *context);
/* }}} */

/* {{{ Symbol fetching helper */
PHPAPI int               php_trace_get_symbol(php_trace_context_t *context, const void *remote, void *symbol, size_t size);
/* }}} */

/* {{{ Cache fetchers */
PHPAPI zend_function*    php_trace_get_function(php_trace_context_t *context, zend_function *symbol);
PHPAPI zend_class_entry* php_trace_get_class(php_trace_context_t *context, zend_class_entry *symbol);
PHPAPI zend_string*      php_trace_get_string(php_trace_context_t *context, zend_string *symbol, zend_bool data);
PHPAPI zend_object*      php_trace_get_object(php_trace_context_t *context, zval *zv, zend_object *symbol);
/* }}} */

/* {{{ zval Copiers */
PHPAPI void php_trace_zval_dtor(php_trace_context_t *context, zval *argv, uint32_t argc);
PHPAPI void php_trace_zval_dup(php_trace_context_t *context, zval *argv, uint32_t argc);
/* }}} */

/* {{{ Default Context */
PHPAPI php_trace_action_result_t php_trace_begin(php_trace_context_t *context, int argc, char **argv);
PHPAPI php_trace_action_result_t php_trace_stack_start(php_trace_context_t *context);
PHPAPI php_trace_action_result_t php_trace_print_frame(php_trace_context_t *context, zend_execute_data *frame, zend_long depth);
PHPAPI php_trace_action_result_t php_trace_stack_finish(php_trace_context_t *context);
PHPAPI php_trace_action_result_t php_trace_schedule(php_trace_context_t *context);
/* }}} */

/* {{{ Loop */
PHPAPI int php_trace_loop(php_trace_context_t *context, int argc, char **argv);
/* }}} */
#endif
