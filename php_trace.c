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

#include <libelf.h>
#include <elfutils/libdwfl.h>

#include <php.h>
#include <php_getopt.h>
#include <php_main.h>

#include <zend_vm.h>

#include <SAPI.h>

#include <php_trace.h>

#define PHP_TRACE_FUNCTION_SIZE(type) \
            ((type == ZEND_INTERNAL_FUNCTION) ? \
                sizeof(zend_internal_function) : \
                sizeof(zend_op_array))

static char *php_trace_dwfl_debuginfo = NULL;

Dwfl_Callbacks php_trace_dwfl_callbacks = {
    .find_elf = dwfl_linux_proc_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .debuginfo_path = &php_trace_dwfl_debuginfo
};

static int php_trace_dwfl_get_module(Dwfl_Module *module, void **debugInfo, const char *moduleName, Dwarf_Addr start, void *ctx) {
    GElf_Addr bias;
    php_trace_context_t *context = (php_trace_context_t *) ctx;
    
    Elf *elf = dwfl_module_getelf(module, &bias);

    if (elf) {
        Elf_Scn *section = NULL;
        Elf_Data *data = NULL;

        while ((section = elf_nextscn(elf, section))) {
            GElf_Sym symbol;
            GElf_Shdr header;
            
            gelf_getshdr(section, &header);
            
            if (header.sh_type == SHT_SYMTAB) {
                int it = 0,
                    end =  header.sh_size / header.sh_entsize;
                data = elf_getdata(section, data);

                while (it < end) {
                    char *symbolName;
                    size_t symbolLength;
                    
                    gelf_getsym(data, it, &symbol);
                    
                    symbolName   = elf_strptr(elf, header.sh_link, symbol.st_name);
                    symbolLength = strlen(symbolName);
                    
                    if (symbolLength == (sizeof("executor_globals")-1)) {
                        if (strncmp(symbolName, "executor_globals", symbolLength) == SUCCESS) {
                            context->executor = (void*) bias + symbol.st_value;
                            
                            return DWARF_CB_ABORT;
                        }
                    }
                    it++;
                }
            }
        }
    }
    
    return DWARF_CB_OK;
}

static int php_trace_dwfl_init(php_trace_context_t *context) {
    Dwfl* dwfl = dwfl_begin(&php_trace_dwfl_callbacks);

    if (!dwfl) {
        return FAILURE;
    }
    
    if (dwfl_linux_proc_report(dwfl, context->pid) != SUCCESS) {
        dwfl_end(dwfl);

        return FAILURE;
    }
    
    dwfl_getmodules(dwfl, php_trace_dwfl_get_module, context, 0);
    dwfl_report_end(dwfl, NULL, NULL);
    dwfl_end(dwfl);
    
    return SUCCESS;
}

const opt_struct php_trace_options[] = {
    {'p', 1, "process"},
    {'m', 1, "max"},
    {'d', 1, "depth"},
    {'f', 1, "frequency"},
    {'a', 0, "args"},
    {'h', 0, "help"},
    {'-', 0, NULL}       /* end of args */
};

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

zend_string* php_trace_get_string(php_trace_context_t *context, zend_string *symbol) {
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
    
    stack.name = php_trace_get_string(context, stack.name);
    
    if (stack.parent) {
        stack.parent = php_trace_get_class(context, stack.parent);
    }
    
    return zend_hash_index_add_mem(&context->classes, (zend_ulong) symbol, &stack, sizeof(zend_class_entry));
}

zend_function* php_trace_get_function(php_trace_context_t *context, zend_function *symbol) {
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
        zend_op *opline;
        
        if (stack.op_array.filename) {
            stack.op_array.filename = php_trace_get_string(context, stack.op_array.filename);
        }
        
        opline = (zend_op*) calloc(stack.op_array.last, sizeof(zend_op));
        
        if (php_trace_get_symbol(context, 
                stack.op_array.opcodes, 
                opline,
                sizeof(zend_op) * stack.op_array.last) != SUCCESS) {
            fprintf(stderr, "couldn't copy instructions\n");
            free(opline);
        }
        
        stack.op_array.opcodes = opline;
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
	            "Usage: %s [options] [flags] -p <target>\n"
	            "Options:\n"
				"           -d --depth      <int> Maximum stack depth       (default 64)\n"
				"           -m --max        <int> Maximum stack traces      (default unlimited)\n"
				"           -f --frequency  <int> Frequency of collection   (default 1000)\n"
				"Flags:\n"
				"           -a --args             Collect arguments\n"
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
        
        free(function->op_array.opcodes);
    }
    
    if (function->common.function_name) {
        free(function->common.function_name);
    }
}

static void php_trace_context_classes_dtor(zval *zv) {
    zend_class_entry *class = Z_PTR_P(zv);
    
    free(class->name);
}

php_trace_action_result_t php_trace_begin(php_trace_context_t *context) {
    if (php_trace_dwfl_init(context) != SUCCESS) {
        fprintf(stderr, "could not initialize DWFL");
        return PHP_TRACE_QUIT;
    }
    
    if (!context->executor) {
        fprintf(stderr, 
            "could not find symbol addresses, stripped binary ?\n");
        return PHP_TRACE_QUIT;
    }

    return PHP_TRACE_OK;
}

php_trace_action_result_t php_trace_stack_start(php_trace_context_t *context) {
    if (php_trace_attach(context) != SUCCESS) {
        fprintf(stderr, 
            "failed to attach to %d\n", context->pid);
        return PHP_TRACE_QUIT;
    }
    
    return PHP_TRACE_OK;
}

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
                argbuflen = snprintf(argbuf, 1024, "string(" ZEND_LONG_FMT ") \"%.*s\"", 
                    Z_STRLEN_P(it), (int) MIN(Z_STRLEN_P(it), 16), Z_STRVAL_P(it));
            break;
            
            case IS_ARRAY:
                argbuflen = snprintf(argbuf, 1024, "array(%u)", zend_hash_num_elements(Z_ARRVAL_P(it)));
            break;
            
            case IS_OBJECT:
                argbuflen = snprintf(argbuf, 1024, "object(%s)", ZSTR_VAL(Z_OBJCE_P(it)->name));
            break;
            
            case IS_RESOURCE:
                argbuflen = snprintf(argbuf, 1024, "resource");
            break;
            
            case IS_REFERENCE:
                argbuflen = snprintf(argbuf, 1024, "reference");
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

php_trace_action_result_t php_trace_frame(php_trace_context_t *context, zend_execute_data *frame, zend_long depth) {         
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
        if (function->type == ZEND_USER_FUNCTION) {
            fprintf(stdout, "#%ld %s in %s::%s%s in %s on line %d\n",
                depth,
                zend_get_opcode_name(instruction->opcode),
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
        if (function->type == ZEND_USER_FUNCTION) {
            fprintf(stdout, "#%ld %s in %s%s in %s on line %d\n",
                depth,
                zend_get_opcode_name(instruction->opcode),
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
    
    return PHP_TRACE_OK;
}

php_trace_action_result_t php_trace_stack_finish(php_trace_context_t *context) {
    if (php_trace_detach(context) != SUCCESS) {
        fprintf(stderr, 
            "failed to detach from %d\n", context->pid);
        return PHP_TRACE_QUIT;
    }
    
    return PHP_TRACE_OK;
}

php_trace_action_result_t php_trace_schedule(php_trace_context_t *context) {
    usleep(context->freq);
    
    return PHP_TRACE_OK;
}

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

static zend_always_inline void php_trace_zval_dup(php_trace_context_t *context, zval *argv, uint32_t argc) {
    zval  *it = argv,
          *end = argv + argc;
             
    while (it < end) {
        switch (Z_TYPE_P(it)) {
            case IS_STRING:
                ZVAL_STR(it, php_trace_get_string(context, Z_STR_P(it)));
            break;
            
            case IS_ARRAY: {
                HashTable *table = calloc(1, sizeof(HashTable));
                
                if (php_trace_get_symbol(context, Z_ARRVAL_P(it), table, sizeof(HashTable)) != SUCCESS) {
                    free(table);
                    
                    ZVAL_NULL(it);
                } else {
                    ZVAL_ARR(it, table);
                }
            } break;
            
            case IS_OBJECT: {
                zend_object *object = calloc(1, sizeof(zend_object));
                
                if (php_trace_get_symbol(context, Z_OBJ_P(it), object, sizeof(zend_object)) != SUCCESS) {
                    free(object);
                    
                    ZVAL_NULL(it);
                } else {
                    object->ce = php_trace_get_class(context, object->ce);
                    ZVAL_OBJ(it, object);
                }
            } break;
        }
        it++;
    }
}

static zend_always_inline void php_trace_zval_dtor(php_trace_context_t *context, zval *argv, uint32_t argc) {
    zval  *it = argv,
          *end = argv + argc;
             
    while (it < end) {
        switch (Z_TYPE_P(it)) {
            case IS_STRING:
                free(Z_STR_P(it));
            break;
            
            case IS_ARRAY: {
                if (Z_ARRVAL_P(it)) {
                    free(Z_ARRVAL_P(it));
                }
            } break;
            
            case IS_OBJECT: {
                if (Z_OBJ_P(it)) {
                    free(Z_OBJ_P(it));
                }
            } break;
        }
        it++;
    }  
}

/* for reference because lxr is down, and I can't remember my own name ...
static zend_always_inline uint32_t zend_vm_calc_used_stack(uint32_t num_args, zend_function *func)
{
	uint32_t used_stack = ZEND_CALL_FRAME_SLOT + num_args;

	if (EXPECTED(ZEND_USER_CODE(func->type))) {
		used_stack += func->op_array.last_var + func->op_array.T - MIN(func->op_array.num_args, num_args);
	}
	return used_stack * sizeof(zval);
}
*/

static zend_always_inline zend_execute_data* php_trace_frame_copy(php_trace_context_t *context, zend_execute_data *frame) {    
    zend_execute_data        stack, 
                             *copy;
    zend_function            *function;
    
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
    
    copy = calloc(1, ZEND_MM_ALIGNED_SIZE(sizeof(zend_execute_data)) + zend_vm_calc_used_stack(ZEND_CALL_NUM_ARGS(&stack), function));
    
    if (!copy) {
        return NULL;
    }
    
    memcpy(copy, &stack, sizeof(zend_execute_data));
    
    copy->func = function;
    
    if (copy->func->type == ZEND_USER_FUNCTION) {
        zend_op_array ops;
        /* TODO cache this symbol */
        if (php_trace_get_symbol(context, stack.func, &ops, sizeof(zend_op_array)) == SUCCESS) {
            copy->opline = function->op_array.opcodes + (stack.opline - ops.opcodes);
        }
    }
    
    /* only copy args where permitted by context */
    if (context->args && ZEND_CALL_NUM_ARGS(copy)) {
        if (php_trace_get_symbol(context, 
                ZEND_CALL_ARG(frame, 1),
                ZEND_CALL_ARG(copy, 1), 
                sizeof(zval) * ZEND_CALL_NUM_ARGS(copy)) != SUCCESS) {
            free(copy);
            return NULL;
        }
        
        php_trace_zval_dup(context, ZEND_CALL_ARG(copy, 1), ZEND_CALL_NUM_ARGS(copy));
    } else {
        ZEND_CALL_NUM_ARGS(copy) = 0;
    }
    
    /* TODO copy vars */
    
    return copy;
}

static zend_always_inline zend_execute_data* php_trace_frame_free(php_trace_context_t *context, zend_execute_data *frame) {
    zend_execute_data *prev = frame->prev_execute_data;
    
    if (ZEND_CALL_NUM_ARGS(frame)) {
        php_trace_zval_dtor(context, 
            ZEND_CALL_ARG(frame, 1), ZEND_CALL_NUM_ARGS(frame));
    }
    
    /* dtor vars */
    
    free(frame);
    
    return prev;
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
        if (context->onBegin(context) == PHP_TRACE_QUIT) {
            zend_hash_destroy(&context->functions);
            zend_hash_destroy(&context->classes);
            return 1;
        }
    }
    
    do {
        zend_long              depth = 1;
        zend_execute_data      *frame, *fp;
        
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
            case 'a': php_trace_context.args  =  1;                                          break;

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
