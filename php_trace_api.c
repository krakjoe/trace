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

#ifndef HAVE_PHP_TRACE_API
#define HAVE_PHP_TRACE_API

#include <php_trace.h>

#define PHP_TRACE_FUNCTION_SIZE(type) \
    (ZEND_USER_CODE(type) ? sizeof(zend_op_array) : sizeof(zend_internal_function))

extern int php_trace_dwfl_init(php_trace_context_t *context);

int php_trace_attach(php_trace_context_t *context) {
    if (ptrace(PTRACE_ATTACH, context->pid, 0, 0) != SUCCESS) {
        return FAILURE;
    }

    waitpid(context->pid, NULL, __WALL);
    
    context->attached = 1;
    
    if (context->onAttach) {
        context->onAttach(context);
    }
    
    return SUCCESS;
}

int php_trace_detach(php_trace_context_t *context) {
    if (ptrace(PTRACE_DETACH, context->pid, 0, 0) != SUCCESS) {
        context->attached = 0;
        return FAILURE;
    }

    waitpid(context->pid, NULL, __WALL);
    
    context->attached = 0;
    
    if (context->onDetach) {
        context->onDetach(context);
    }
    
    return SUCCESS;
}

int php_trace_get_symbol(php_trace_context_t *context, const void *remote, void *symbol, size_t size) {
    struct iovec local;
    struct iovec target;

    local.iov_base = symbol;
    local.iov_len  = size;
    target.iov_base = (void*) remote;
    target.iov_len = size;
    
    if (process_vm_readv(context->pid, &local, 1, &target, 1, 0) != size) {
        return FAILURE;
    }

    return SUCCESS;
}

zend_object* php_trace_get_object(php_trace_context_t *context, zval *zv, zend_object *symbol) {
    zend_object stack,
                *object;
    
    if ((object = zend_hash_index_find_ptr(&context->objects, (zend_ulong) symbol))) {
        if (object->handlers == (void*) symbol) {
            return object;
        }
    }
                
    if (php_trace_get_symbol(context, symbol, &stack, sizeof(zend_object)) != SUCCESS) {
        return NULL;
    }
    
    /* TODO copy inline properties ? */
    
    /* TODO copy properties table ? */
    
    stack.ce = 
        php_trace_get_class(context, stack.ce);

    stack.handlers = (void*) symbol;
        
    return zend_hash_index_update_mem(&context->objects, (zend_ulong) symbol, &stack, sizeof(zend_object));
}

zend_string* php_trace_get_string(php_trace_context_t *context, zend_string *symbol, zend_bool data) {
    zend_string  *string;
    size_t        len;
    
    /* TODO cache strings based on hval ? */
    
    if (php_trace_get_symbol(
            context, 
            ((char*)symbol) + XtOffsetOf(zend_string, len),
            &len, sizeof(size_t)) != SUCCESS) {
        return NULL;
    }
    
    if (data) {
        string = zend_string_alloc(len, 1);
        
        if (!string || php_trace_get_symbol(
                context, 
                symbol,
                string, ZEND_MM_ALIGNED_SIZE(_ZSTR_STRUCT_SIZE(len))) != SUCCESS) {
            if (string) {
                free(string);
            }
            return NULL;
        }
    } else {
        string = calloc(1, sizeof(zend_string));

        ZSTR_LEN(string) = len;
        ZSTR_VAL(string)[0] = 0;
    }
    
    return string;
}

zend_class_entry* php_trace_get_class(php_trace_context_t *context, zend_class_entry *symbol) {
    zend_class_entry stack,
                     *class = zend_hash_index_find_ptr(&context->classes, (zend_ulong) symbol);
    
    if (class) {
        return class;
    }
    
    if (php_trace_get_symbol(
            context, 
            symbol,
            &stack, sizeof(zend_class_entry)) != SUCCESS) {
        return NULL;
    }
    
    stack.name = php_trace_get_string(context, stack.name, 1);
    
    if (stack.parent) {
        stack.parent = php_trace_get_class(context, stack.parent);
    }
    
    return zend_hash_index_add_mem(&context->classes, (zend_ulong) symbol, &stack, sizeof(zend_class_entry));
}

zend_function* php_trace_get_function(php_trace_context_t *context, zend_function *symbol) {
    zend_uchar     type;
    zend_function *heap;
    zend_function *function = zend_hash_index_find_ptr(&context->functions, (zend_ulong) symbol);
    
    if (function) {
        return function;
    }

    if (php_trace_get_symbol(
            context, 
            symbol,
            &type, sizeof(zend_uchar)) != SUCCESS) {
        return NULL;
    }
    
    if (type == ZEND_INTERNAL_FUNCTION) {
        heap = calloc(1, sizeof(zend_internal_function));
    } else heap = calloc(1, sizeof(zend_op_array));
    
    if (php_trace_get_symbol(
            context, 
            symbol,
            heap, PHP_TRACE_FUNCTION_SIZE(type)) != SUCCESS) {
        return NULL;
    }
    
    if (heap->common.function_name) {
        heap->common.function_name = php_trace_get_string(context, heap->common.function_name, 1);
    }
    
    if (ZEND_USER_CODE(type)) {
        if (heap->op_array.filename) {
            heap->op_array.filename = php_trace_get_string(context, heap->op_array.filename, 1);
        }
        
        if (context->stack) {
            if (heap->op_array.last_var) {
                uint32_t var = 0;
                zend_string **vars = calloc(heap->op_array.last_var, sizeof(zend_string*));
                 
                php_trace_get_symbol(
                    context, 
                    heap->op_array.vars, 
                    vars,
                    sizeof(zend_string*) * heap->op_array.last_var);
                
                while (var < heap->op_array.last_var) {
                    vars[var] = php_trace_get_string(context, vars[var], 1);
                    var++;
                }
                
                heap->op_array.vars = vars;
            }
            
            if (heap->op_array.last_literal) {
                /* todo literals */
            }
        } else {
            heap->op_array.last_var     = 0;
            heap->op_array.vars         = NULL;
            heap->op_array.last_literal = 0;
            heap->op_array.literals     = NULL;
        }
    }
    
    if (heap->common.scope) {
        heap->common.scope = php_trace_get_class(context, heap->common.scope);
    }
    
    return zend_hash_index_add_ptr(&context->functions, (zend_ulong) symbol, heap);
}

php_trace_action_result_t php_trace_begin(php_trace_context_t *context, int argc, char **argv) {
    if (!context->executor) {
        if (php_trace_dwfl_init(context) != SUCCESS) {
            fprintf(stderr, 
                "could not initialize for process %d, "
                "non-existent process ?\n",
                context->pid);
            return PHP_TRACE_QUIT;
        }
        
        if (!context->executor) {
            fprintf(stderr, 
                "could not find symbol addresses for process %d, "
                "stripped binary ?\n",
                context->pid);
            return PHP_TRACE_QUIT;
        }
    }
    
    return PHP_TRACE_OK;
}

php_trace_action_result_t php_trace_stack_start(php_trace_context_t *context) {
    if (php_trace_attach(context) != SUCCESS) {
        return PHP_TRACE_QUIT;
    }
    
    return PHP_TRACE_OK;
}

php_trace_action_result_t php_trace_stack_finish(php_trace_context_t *context) {
    if (php_trace_detach(context) != SUCCESS) {
        return PHP_TRACE_QUIT;
    }
    
    return PHP_TRACE_OK;
}

php_trace_action_result_t php_trace_schedule(php_trace_context_t *context) {
    usleep(context->freq);
    
    return PHP_TRACE_OK;
}

#endif
