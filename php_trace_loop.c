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

#ifndef HAVE_PHP_TRACE_LOOP
#define HAVE_PHP_TRACE_LOOP

#include <php_trace.h>

static php_trace_context_t *php_trace_ctx;

static zend_always_inline zend_execute_data* php_trace_get_frame(php_trace_context_t *context) {    
    zend_executor_globals executor;
    
    if (php_trace_get_symbol(context, 
            context->executor, 
            &executor, 
            sizeof(zend_executor_globals)) != SUCCESS) {
        return NULL;
    }

    return executor.current_execute_data;
}

static zend_always_inline uint32_t php_trace_frame_used_stack(zend_execute_data *frame, zend_function *function) {
    uint32_t used =  ZEND_CALL_FRAME_SLOT;
    
    if (ZEND_USER_CODE(function->type)) {
        used += function->op_array.last_var;
    } else {
        used += ZEND_CALL_NUM_ARGS(frame);
    }
    
    return used * sizeof(zval);
}

static zend_always_inline size_t php_trace_frame_stack_size(zend_execute_data *frame, zend_function *function) {
    if (ZEND_USER_CODE(function->type)) {
        /* not interested in temp vars */
        return function->op_array.last_var;
    }
    
    return ZEND_CALL_NUM_ARGS(frame);
}

static zend_always_inline zend_execute_data* php_trace_frame_copy(php_trace_context_t *context, zend_execute_data *frame) {    
    zend_execute_data        stack, 
                             *copy;
    zend_function            *function;
    size_t                    size;
    
    if (php_trace_get_symbol(
            context, 
            frame,
            &stack, sizeof(zend_execute_data)) != SUCCESS) {
        return NULL;                
    }
    
    function = php_trace_get_function(context, stack.func);
    
    if (!function) {
        return NULL;
    }
    
    size = php_trace_frame_used_stack(&stack, function);
    
    copy = calloc(1, ZEND_MM_ALIGNED_SIZE(size));
    
    if (((!copy) || (php_trace_get_symbol(context, frame, copy, ZEND_MM_ALIGNED_SIZE(size)) != SUCCESS))) {
        if (copy) {
            free(copy);
        }
        return NULL;
    }
    
    copy->func = function;
    
    if (ZEND_USER_CODE(copy->func->type)) {
        copy->opline = calloc(1, sizeof(zend_op));
        
        if (php_trace_get_symbol(context, stack.opline, (void*) copy->opline, sizeof(zend_op)) != SUCCESS) {
            copy->opline = NULL;
        }
    }
    
    if (context->stack) {
        php_trace_zval_dup(context, 
            ZEND_CALL_ARG(copy, 1),
            php_trace_frame_stack_size(copy, copy->func));
    } else {
        ZEND_CALL_NUM_ARGS(copy) = 0;
    }
    
    return copy;
}

static zend_always_inline zend_execute_data* php_trace_frame_free(php_trace_context_t *context, zend_execute_data *frame) {
    zend_execute_data *prev = frame->prev_execute_data;
    
    if (context->stack) {
        php_trace_zval_dtor(context, 
            ZEND_CALL_ARG(frame, 1), 
            php_trace_frame_stack_size(frame, frame->func));
    }
    
    if (ZEND_USER_CODE(frame->func->type) && frame->opline) {
        free((void*)frame->opline);
    }
    
    free(frame);
    
    return prev;
}

static void php_trace_context_functions_dtor(zval *zv) {
    zend_function *function = Z_PTR_P(zv);
    
    if (ZEND_USER_CODE(function->type)) {
        if (function->op_array.filename) {
            free(function->op_array.filename);
        }
        
        if (function->op_array.last_var) {
            uint32_t  var = 0;

            while (var < function->op_array.last_var) {
                free(function->op_array.vars[var]);
                var++;
            }
            
            free(function->op_array.vars);
        }
    }
    
    if (function->common.function_name) {
        free(function->common.function_name);
    }
    
    free(function);
}

static void php_trace_context_classes_dtor(zval *zv) {
    zend_class_entry *class = Z_PTR_P(zv);
    
    free(class->name);
    free(class);
}

static void php_trace_context_objects_dtor(zval *zv) {
    zend_object *object = Z_PTR_P(zv);
    
    free(object);
}

static void php_trace_interrupt(int signum, siginfo_t *info, void *ucontext) {
    php_trace_ctx->interrupted = 1;
}

static zend_always_inline void php_trace_signal(int signo, void *handler) {
    struct sigaction sa;
    
    memset(&sa, 0, sizeof(struct sigaction));
    
    sa.sa_sigaction = handler;
    sa.sa_flags     = SA_SIGINFO;
    
    sigemptyset(&sa.sa_mask);
    
    sigaction(signo,  &sa, NULL);
}

int php_trace_loop(php_trace_context_t *context, int argc, char **argv) {
    php_trace_ctx = context;
    
    php_trace_signal(SIGINT,  php_trace_interrupt);
    
    if (context->onBegin) {
        if (context->onBegin(context, argc, argv) == PHP_TRACE_QUIT) {
            return 1;
        }
    }
    
    zend_hash_init(
        &context->functions, 
        32, 
        NULL, php_trace_context_functions_dtor, 1);    
    zend_hash_init(&context->classes, 
        32, 
        NULL, php_trace_context_classes_dtor, 1);
    zend_hash_init(&context->objects, 
        32, 
        NULL, php_trace_context_objects_dtor, 1);
    
    do {
        zend_long              depth = 1;
        zend_execute_data      *frame, *fp;
        
        if (context->interrupted) {
            break;
        }
        
        if (context->onStackStart) {
            if (context->onStackStart(context) == PHP_TRACE_QUIT) {
                break;
            }
        }
        
        fp = php_trace_get_frame(context);
        
        do {
            if (!fp || !(frame = php_trace_frame_copy(context, fp))) {
                context->samples--;
                break;
            }
            
            if (context->onFrame(context, frame, depth++) == PHP_TRACE_STOP) {
                php_trace_frame_free(context, frame);
                break;
            }
            
            fp = php_trace_frame_free(context, frame);
            
            if ((depth > context->depth) && (context->depth > 0)) {
                break;
            }
        } while (fp);

        if (context->onStackFinish) {
            if (context->onStackFinish(context) == PHP_TRACE_QUIT) {
                break;
            }
        }

        if (context->onSchedule) {
            if (context->onSchedule(context) == PHP_TRACE_QUIT) {
                break;
            }
        }
    } while ((++context->samples < context->max) || (context->max == -1));
    
    if (context->attached) {
        php_trace_detach(context);
    }

    zend_hash_destroy(&context->functions);
    zend_hash_destroy(&context->classes);
    zend_hash_destroy(&context->objects);
    
    if (context->onEnd) {
        context->onEnd(context);
    }
    
    return 0;
}
#endif
