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

#ifndef HAVE_PHP_TRACE
#define HAVE_PHP_TRACE

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>

#include <php.h>
#include <php_getopt.h>
#include <php_main.h>

#include <zend_vm.h>

#include <SAPI.h>

#include <php_trace.h>

#ifdef HAVE_GCC_GLOBAL_REGS
# if defined(__GNUC__) && ZEND_GCC_VERSION >= 4008 && defined(i386)
#  define PHP_TRACE_FP_REG(r) r.esi
#  define PHP_TRACE_IP_REG(r) r.edi
# elif defined(__GNUC__) && ZEND_GCC_VERSION >= 4008 && defined(__x86_64__)
#  define PHP_TRACE_FP_REG(r) r.r14
#  define PHP_TRACE_IP_REG(r) r.r15
# elif defined(__GNUC__) && ZEND_GCC_VERSION >= 4008 && defined(__powerpc64__)
#  define PHP_TRACE_FP_REG(r) r.28
#  define PHP_TRACE_IP_REG(r) r.29
# elif defined(__IBMC__) && ZEND_GCC_VERSION >= 4002 && defined(__powerpc64__)
#  define PHP_TRACE_FP_REG(r) r.28
#  define PHP_TRACE_IP_REG(r) r.29
# endif
#else
#error "php-trace needs global regs"
#endif

#define PHP_TRACE_FUNCTION_SIZE(type) ((type == ZEND_INTERNAL_FUNCTION) ? \
                                            sizeof(zend_internal_function) : \
                                            sizeof(zend_op_array))
const opt_struct php_trace_options[] = {
    {'p', 1, "process"},
    {'m', 1, "max"},
    {'d', 1, "depth"},
    {'f', 1, "frequency"},
    {'h', 0, "help"},
    {'-', 0, NULL}       /* end of args */
};

static zend_always_inline int php_trace_attach(php_trace_context_t *context) {
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

static zend_always_inline int php_trace_detach(php_trace_context_t *context) {
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

static zend_always_inline int php_trace_get_symbol(php_trace_context_t *context, const void *remote, void *symbol, size_t size) {
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

static zend_always_inline zend_string* php_trace_get_string(php_trace_context_t *context, zend_string *symbol) {
    zend_string stack,
               *string;
    
    if (php_trace_get_symbol(
            context, 
            symbol,
            &stack, ZEND_MM_ALIGNED_SIZE(_ZSTR_STRUCT_SIZE(0))) != SUCCESS) {
        return NULL;
    }
    
    string = zend_string_alloc(stack.len, 1);
    
    if (php_trace_get_symbol(
            context, 
            symbol,
            string, ZEND_MM_ALIGNED_SIZE(_ZSTR_STRUCT_SIZE(stack.len))) != SUCCESS) {
        free(string);
        return NULL;
    }
    
    return string;
}

static zend_always_inline zend_class_entry* php_trace_get_class(php_trace_context_t *context, zend_class_entry *symbol) {
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
    
    stack.name = php_trace_get_string(context, stack.name);
    
    if (stack.parent) {
        stack.parent = php_trace_get_class(context, stack.parent);
    }
    
    return zend_hash_index_add_mem(&context->classes, (zend_ulong) symbol, &stack, sizeof(zend_class_entry));
}

static zend_always_inline zend_function* php_trace_get_function(php_trace_context_t *context, zend_function *symbol) {
    zend_function stack;
    zend_function *function = zend_hash_index_find_ptr(&context->functions, (zend_ulong) symbol);
    
    if (function) {
        return function;
    }

    if (php_trace_get_symbol(
            context, 
            symbol,
            &stack, sizeof(zend_function)) != SUCCESS) {
        return NULL;
    }
    
    if (stack.common.function_name) {
        stack.common.function_name = php_trace_get_string(context, stack.common.function_name);
    }
    
    if (stack.type == ZEND_USER_FUNCTION) {
        if (stack.op_array.filename) {
            stack.op_array.filename = php_trace_get_string(context, stack.op_array.filename);
        }
    }
    
    if (stack.common.scope) {
        stack.common.scope = php_trace_get_class(context, stack.common.scope);
    }
    
    return zend_hash_index_add_mem(&context->functions, (zend_ulong) symbol, &stack, PHP_TRACE_FUNCTION_SIZE(stack.type));
}

static void php_trace_usage(char *argv0) {
    char *prog;

	prog = strrchr(argv0, '/');
	if (prog) {
		prog++;
	} else {
		prog = "php-trace";
	}

	fprintf(stdout,
	            "Usage: %s [options] -p <target>\n"
				"           -d --depth      <int> Maximum stack depth       (default 64)\n"
				"           -m --max        <int> Maximum stack traces      (default unlimited)\n"
				"           -f --frequency  <int> Frequency of collection   (default 1000)\n"
				"Example Usage:\n"
				"%s -p 1337 -d1         - trace process 1337 generating traces with a single frame\n"
				"%s -p 1337 -d128 -m100 - trace process 1337 generating traces 128 frames deep stopping at 100 traces\n"
				, prog, prog, prog);
}

static void php_trace_context_functions_dtor(zval *zv) {
    zend_function *function = Z_PTR_P(zv);
    
    if (function->type == ZEND_USER_FUNCTION) {
        if (function->op_array.filename) {
            free(function->op_array.filename);
        }
    }
    
    if (function->common.function_name) {
        free(function->common.function_name);
    }
}

static void php_trace_context_classes_dtor(zval *zv) {
    zend_class_entry *class = Z_PTR_P(zv);
    
    free(class->name);
}

php_trace_action_t php_trace_frame_print(php_trace_context_t *context, zend_execute_data *frame, zend_long depth) {
    uint32_t it = 1,
             end = depth;
             
    zend_function *function = frame->func;
    const zend_op *instruction = frame->opline;
    
    if (depth > 1) {
        fprintf(stdout, "|");
    }
    
    while (it < end) {
        fprintf(stdout, "-");
        it++;
    }
    
    if (depth > 1) {
        fprintf(stdout, ">");
    }
    
    if (function) {
        if (function->common.scope) {
            if (function->type == ZEND_USER_FUNCTION) {
                fprintf(stdout, "[%p] %p -> %p %s::%s %s in %s on line %d\n",
                    frame, 
                    frame->func, function, 
                    function->common.scope ?
                        ZSTR_VAL(function->common.scope->name) :
                        "unknown",
                    function->common.function_name ?
                        ZSTR_VAL(function->common.function_name) :
                        "main",
                    zend_get_opcode_name(instruction->opcode),
                    function->op_array.filename ?
                        ZSTR_VAL(function->op_array.filename) :
                        "unknown",
                    instruction->lineno);
            } else {
                fprintf(stdout, "[%p] %p -> %p %s::%s\n", 
                    frame, 
                    frame->func, function, 
                    ZSTR_VAL(function->common.scope->name),
                    ZSTR_VAL(function->common.function_name));
            }
        } else {
            if (function->type == ZEND_USER_FUNCTION) {
                fprintf(stdout, "[%p] %p -> %p %s %s in %s on line %d\n",
                    frame, 
                    frame->func, function, 
                    function->common.function_name ?
                        ZSTR_VAL(function->common.function_name) :
                        "main",
                    zend_get_opcode_name(instruction->opcode),
                    function->op_array.filename ?
                        ZSTR_VAL(function->op_array.filename) :
                        "unknown",
                    instruction->lineno);
            } else {
                fprintf(stdout, "[%p] %p -> %p %s\n", 
                    frame, 
                    frame->func, function, 
                    ZSTR_VAL(function->common.function_name));
            }
        }
    } else {
        fprintf(stdout, "[%p] %p\n", 
                frame, 
                frame->func);
    }
    
    return PHP_TRACE_OK;
}

static zend_always_inline zend_execute_data* php_trace_get_frame(php_trace_context_t *context) {    
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, context->pid, NULL, &regs) != SUCCESS) {
        return NULL;
    }
    
    return (zend_execute_data*) PHP_TRACE_FP_REG(regs);
}

int php_trace_main(php_trace_context_t *context, int argc, char **argv) {
    zend_hash_init(
        &context->functions, 
        32, 
        NULL, php_trace_context_functions_dtor, 1);    
    zend_hash_init(&context->classes, 
        32, 
        NULL, php_trace_context_classes_dtor, 1);
    
    if (context->onBegin) {
        context->onBegin(context);
    }
    
    do {
        zend_long              depth = 1;
        zend_execute_data      frame, call, *fp;
        zend_op                instruction;
        
        if (php_trace_attach(context) != SUCCESS) {
            fprintf(stderr, "failed to attach to %d\n", context->pid);
            break;
        }
        
        if (context->onStackStart) {
            if (context->onStackStart(context) == PHP_TRACE_QUIT) {
                break;
            }
        }
        
        fp = php_trace_get_frame(context);
        
        do {
            memset(&frame,       0, sizeof(zend_execute_data));
            memset(&call,        0, sizeof(zend_execute_data));
            memset(&instruction, 0, sizeof(zend_op));
        
            if (!fp || php_trace_get_symbol(
                    context, 
                    fp,
                    &frame, sizeof(zend_execute_data)) != SUCCESS) {
                context->samples--;
                break;
            }
            
            frame.func = php_trace_get_function(context, frame.func);
            
            if (frame.func && 
                frame.func->type == ZEND_USER_FUNCTION && 
                php_trace_get_symbol(
                    context, 
                    frame.opline,
                    &instruction, sizeof(zend_op)) == SUCCESS) {
                frame.opline = &instruction;
            } else if (frame.func) {
                frame.opline = NULL;
            } else {
                frame.func = NULL;
            }
            
            if (frame.call && php_trace_get_symbol(
                        context,
                        frame.call,
                        &call, sizeof(zend_execute_data)) == SUCCESS) {
                
                if (call.func) {
                    call.func = php_trace_get_function(context, call.func);
                }
                
                if (instruction.opcode == ZEND_DO_ICALL) {
                    if (context->onFrame(context, &call, depth++) == PHP_TRACE_STOP) {
                        break;
                    }
                }
                
                frame.call = &call;
            } else {
                frame.call = NULL;
            }
            
            if (context->onFrame(context, &frame, depth++) == PHP_TRACE_STOP) {
                break;
            }
            
            if ((depth > context->depth) && (context->depth > 0)) {
                break;
            }
        } while ((fp = frame.prev_execute_data));
        
        if (php_trace_detach(context) != SUCCESS) {
            fprintf(stderr, "failed to detach from %d\n", context->pid);
            break;
        }
        
        if (context->onStackFinish) {
            if (context->onStackFinish(context) == PHP_TRACE_QUIT) {
                break;
            }
        }

        usleep(context->freq);
    } while ((++context->samples < context->max) || (context->max == -1));
    
    if (context->attached) {
        php_trace_detach(context);
    }
    
    if (context->onEnd) {
        context->onEnd(context);
    }
    
    zend_hash_destroy(&context->functions);
    zend_hash_destroy(&context->classes);
    
    return 0;
}

int main(int argc, char **argv) {
    char *php_trace_optarg = NULL;
    int   php_trace_optind = 1,
          php_trace_optcur = 0,
          php_trace_status = 0;
    pid_t php_trace_forked = 0;
    
    while ((php_trace_optcur = php_getopt(argc, argv, php_trace_options, &php_trace_optarg, &php_trace_optind, 0, 2)) != -1) {
        switch (php_trace_optcur) {
            case 'p': php_trace_context.pid   =  (pid_t) strtol(php_trace_optarg, NULL, 10); break;
            case 'm': php_trace_context.max   =  strtoul(php_trace_optarg, NULL, 10);        break;
            case 'd': php_trace_context.depth =  strtoul(php_trace_optarg, NULL, 10);        break;
            case 'f': php_trace_context.freq  =  strtoul(php_trace_optarg, NULL, 10);        break;
            
            case 'h': {
                php_trace_usage(argv[0]);
                return 0;
            } break;
            
            default:
                break;
        }
    }

    if (!php_trace_context.pid) {
        php_trace_usage(argv[0]);
        return 1;
    }
    
    php_trace_forked = fork();

    if (php_trace_forked == SUCCESS) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[php_trace_optind], argv + php_trace_optind);
        fprintf(stderr, 
            "failed to fork tracee %s\n", strerror(errno));
        return 1;
    } else if (php_trace_forked < 0) {
        fprintf(stderr, 
            "failed to fork %s\n", strerror(errno));
        return 1;
    }
    
    waitpid(php_trace_forked, &php_trace_status, 0);
    
    ptrace(PTRACE_DETACH, php_trace_forked, NULL, NULL);
    
    php_trace_main(
        &php_trace_context, argc, argv);
    
    waitpid(php_trace_forked, NULL, 0);
    return 0;
}


#endif
