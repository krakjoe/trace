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

#ifndef HAVE_PHP_TRACE_ZVAL
#define HAVE_PHP_TRACE_ZVAL

#include <php.h>
#include <php_trace.h>

void php_trace_zval_dup(php_trace_context_t *context, zval *argv, uint32_t argc) {
    zval  *it = argv,
          *end = argv + argc;
             
    while (it < end) {
        if (!Z_COUNTED_P(it)) {
            it++;
            continue;
        }
        
        switch (Z_TYPE_P(it)) {
            case IS_STRING: {
                zend_string *str = php_trace_get_string(context, Z_STR_P(it), context->strData);
                
                if (str) {
                    ZVAL_STR(it, str);
                } else {
                    ZVAL_NULL(it);
                }
            } break;
            
            case IS_ARRAY: {
                HashTable *table = calloc(1, sizeof(HashTable));
                
                if (!table || php_trace_get_symbol(context, Z_ARRVAL_P(it), table, sizeof(HashTable)) != SUCCESS) {
                    if (table) {
                        free(table);
                    }
                    
                    ZVAL_NULL(it);
                } else if (context->arData){
                    void *arData = calloc(table->nNumOfElements, sizeof(Bucket));
                    
                    if (!arData || php_trace_get_symbol(context, table->arData, arData, sizeof(Bucket) * table->nNumOfElements) != SUCCESS) {
                        if (arData) {
                            free(arData);
                        }
                        free(table);
                        
                        ZVAL_NULL(it);
                    } else {
                        Bucket *bit = arData,
                               *bend = bit + table->nNumOfElements;

                        while (bit < bend) {
                            if (Z_ISUNDEF(bit->val)) {
                                bit++;
                                continue;
                            }
                            
                            if (bit->key) {
                                bit->key = php_trace_get_string(context, bit->key, 1);
                            }
                            
                            if (Z_COUNTED(bit->val)) {
                                php_trace_zval_dup(context, &bit->val, 1);
                            }
                            bit++;
                        }
                        
                        table->arData = arData;
                        
                        Z_ARRVAL_P(it) = table;
                    }
                } else {
                    Z_ARRVAL_P(it) = table;
                }
            } break;
            
            case IS_OBJECT: {
                zend_object *object = php_trace_get_object(context, it, Z_OBJ_P(it));
                
                if (object){
                    ZVAL_OBJ(it, object);
                } else {
                    ZVAL_NULL(it);
                }
            } break;
        }
        it++;
    }
}

void php_trace_zval_dtor(php_trace_context_t *context, zval *argv, uint32_t argc) {
    zval  *it = argv,
          *end = argv + argc;
             
    while (it < end) {
        if (!Z_COUNTED_P(it)) {
            it++;
            continue;
        }
        
        switch (Z_TYPE_P(it)) {
            case IS_STRING:
                free(Z_STR_P(it));
            break;
            
            case IS_ARRAY: {
                HashTable *table = Z_ARRVAL_P(it);
                if (table) {
                    if (context->arData) {
                        Bucket *bit = table->arData,
                           *bend = bit + table->nNumOfElements;
                    
                        while (bit < bend) {
                            if (Z_ISUNDEF(bit->val)) {
                                bit++;
                                continue;
                            }
                            
                            if (bit->key) {
                                free(bit->key);
                            }
                            
                            if (Z_COUNTED(bit->val)) {
                                php_trace_zval_dtor(context, &bit->val, 1);
                            }
                            
                            bit++;
                        }
                        
                        free(table->arData);
                    }
                    free(table);
                }
            } break;
        }
        it++;
    }
}
#endif
