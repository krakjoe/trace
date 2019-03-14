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

#ifndef HAVE_PHP_TRACE_PRINT
#define HAVE_PHP_TRACE_PRINT

#include <php_trace.h>

static zend_always_inline void php_trace_frame_args(php_trace_context_t *context, zend_execute_data *frame, char *buffer, size_t buflen) {    
    size_t bufpos = 0;
    zval *it = ZEND_CALL_ARG(frame, 1),
         *end = it + ZEND_CALL_NUM_ARGS(frame);
    
    memset(buffer, 0, buflen);
    memcpy(&buffer[bufpos], "(", sizeof("(")-1);
    bufpos += (sizeof(")")-1);
    
    while (it < end && bufpos < buflen) {
        char argbuf[1024];
        size_t argbuflen = 0;
        
        switch (Z_TYPE_P(it)) {
            case IS_NULL:
                argbuflen = snprintf(argbuf, 1024, "null");
            break;
            
            case IS_DOUBLE:
                argbuflen = snprintf(argbuf, 1024, "float(%f)", Z_DVAL_P(it));
            break;
            
            case IS_LONG:
                argbuflen = snprintf(argbuf, 1024, "int(" ZEND_LONG_FMT ")", Z_LVAL_P(it));
            break;
            
            case IS_STRING:
                argbuflen = snprintf(argbuf, 1024, "string(" ZEND_LONG_FMT ")", Z_STRLEN_P(it));
            break;
            
            case IS_ARRAY:
                argbuflen = snprintf(argbuf, 1024, "array(%u)", zend_hash_num_elements(Z_ARRVAL_P(it)));
            break;
            
            case IS_OBJECT:
                argbuflen = snprintf(argbuf, 1024, "object(%s) #%u", 
                    ZSTR_VAL(Z_OBJCE_P(it)->name), Z_OBJ_P(it)->handle);
            break;
            
            case IS_RESOURCE:
                argbuflen = snprintf(argbuf, 1024, "resource(#%ld)", Z_LVAL_P(it));
            break;
            
            case IS_REFERENCE:
                argbuflen = snprintf(argbuf, 1024, "reference");
            break;
            
            case IS_FALSE:
            case IS_TRUE:
                argbuflen = snprintf(argbuf, 1024, "bool(%s)",
                    Z_TYPE_P(it) == IS_TRUE ? "true" : "false");
            break;
        }
        
        if (argbuflen) {
            if ((argbuflen + bufpos) > buflen) {
                break;
            }
            
            memcpy(&buffer[bufpos], argbuf, argbuflen);
            
            bufpos += argbuflen;
            
            if ((bufpos + (sizeof(", ")-1)) > buflen) {
                break;
            }
            
            if ((it + 1) < end) {
                memcpy(&buffer[bufpos], ", ", sizeof(", ")-1);
                
                bufpos += (sizeof(", ")-1);
            }
        }
        it++;
    }
    
    memcpy(&buffer[bufpos], ")", sizeof(")")-1);
    bufpos += (sizeof(")")-1);
    
    buffer[bufpos] = 0;
}

php_trace_action_result_t php_trace_print_frame(php_trace_context_t *context, zend_execute_data *frame, zend_long depth) {         
    zend_function *function    = frame->func;
    const zend_op *instruction = frame->opline;
    
    char argbuf[8192] = {0};
    size_t argbuflen = 8192;
    
    uint32_t it = 1, end = depth;
    
    if (depth > 1) {
        fprintf(stdout, "|");
    }
    
    while (it < end) {
        fprintf(stdout, "-");
        it++;
    }
    
    if (depth > 1) {
        fprintf(stdout, "> ");
    }
    
    if (ZEND_CALL_NUM_ARGS(frame)) {
        php_trace_frame_args(context, frame, (char*) argbuf, argbuflen);
    }
    
    if (function->common.scope) {
        if (ZEND_USER_CODE(function->type)) {
            fprintf(stdout, "#%ld %s::%s%s in %s on line %d\n",
                depth,
                function->common.scope ?
                    ZSTR_VAL(function->common.scope->name) :
                    "unknown",
                function->common.function_name ?
                    ZSTR_VAL(function->common.function_name) :
                    "main",
                *argbuf ? argbuf : "",
                function->op_array.filename ?
                    ZSTR_VAL(function->op_array.filename) :
                    "unknown",
                instruction->lineno);
        } else {
            fprintf(stdout, "#%ld %s::%s%s <internal>\n", 
                depth,
                ZSTR_VAL(function->common.scope->name),
                ZSTR_VAL(function->common.function_name),
                *argbuf ? argbuf : "");
        }
    } else {
        if (ZEND_USER_CODE(function->type)) {
            fprintf(stdout, "#%ld %s%s in %s on line %d\n",
                depth,
                function->common.function_name ?
                    ZSTR_VAL(function->common.function_name) :
                    "main",
                *argbuf ? argbuf : "",
                function->op_array.filename ?
                    ZSTR_VAL(function->op_array.filename) :
                    "unknown",
                instruction->lineno);
        } else {
            fprintf(stdout, "#%ld %s%s <internal>\n",
                depth, 
                ZSTR_VAL(function->common.function_name),
                *argbuf ? argbuf : "");
        }
    }
    
    fflush(stdout);
    
    return PHP_TRACE_OK;
}
#endif
