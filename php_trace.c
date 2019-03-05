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

#define PHP_TRACE_FUNCTION_SIZE(type) ((type == ZEND_INTERNAL_FUNCTION) ? \
                                            sizeof(zend_internal_function) : \
                                            sizeof(zend_op_array))

static char *php_trace_dwfl_debuginfo = NULL;

Dwfl_Callbacks php_trace_dwfl_callbacks = {
    .find_elf = dwfl_linux_proc_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .debuginfo_path = &php_trace_dwfl_debuginfo
};

const opt_struct php_trace_options[] = {
    {'p', 1, "process"},
    {'m', 1, "max"},
    {'d', 1, "depth"},
    {'f', 1, "frequency"},
    {'h', 0, "help"},
    {'-', 0, NULL}       /* end of args */
};

static int php_trace_dwfl_get_module(Dwfl_Module *module, void **debugInfo, const char *moduleName, Dwarf_Addr start, void *ctx) {
    GElf_Addr php_trace_bias;
    php_trace_context_t *context = (php_trace_context_t *) ctx;
    
    Elf *php_trace_elf = dwfl_module_getelf(module, &php_trace_bias);
    
    zend_hash_init(&context->symbols, 64, NULL, NULL, 1);

    if (php_trace_elf) {
        Elf_Scn *section = NULL;
        Elf_Data *data = NULL;

        while ((section = elf_nextscn(php_trace_elf, section))) {
            GElf_Sym symbol;
            GElf_Shdr header;
            
            gelf_getshdr(section, &header);
            
            if (header.sh_type == SHT_SYMTAB) {
                int it = 0,
                    end =  header.sh_size / header.sh_entsize;
                data = elf_getdata(section, data);

                while (it < end) {
                    char *symbolName;
                    
                    gelf_getsym(data, it, &symbol);
                    
                    symbolName = elf_strptr(php_trace_elf, header.sh_link, symbol.st_name);
                   
                    zend_hash_str_add_ptr(
                        &context->symbols,
                        symbolName, 
                        strlen(symbolName), 
                        (void*) php_trace_bias + symbol.st_value);

                    it++;
                }
            }
        }
    }
    
    return DWARF_CB_ABORT;
}

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

static zend_always_inline int php_trace_get_symbol(pid_t pid, HashTable *symbols, void *name, size_t length, void *symbol, size_t size) {
    struct iovec local;
    struct iovec target;
    ssize_t rv;

    local.iov_base = symbol;
    local.iov_len  = size;
    target.iov_base = symbols ? zend_hash_str_find_ptr(
            symbols, (const char*) name, length) : name;
    target.iov_len = size;

    rv = process_vm_readv(pid, &local, 1, &target, 1, 0);

    if (rv != size) {
        return FAILURE;
    }

    return SUCCESS;
}

static zend_always_inline zend_string* php_trace_get_string(php_trace_context_t *context, zend_string *symbol) {
    zend_string stack,
               *string;
    
    if (php_trace_get_symbol(
            context->pid, 
            NULL, 
            symbol, 0,
            &stack, ZEND_MM_ALIGNED_SIZE(_ZSTR_STRUCT_SIZE(0))) != SUCCESS) {
        return NULL;
    }
    
    string = zend_string_alloc(stack.len, 1);
    
    if (php_trace_get_symbol(
            context->pid, 
            NULL, 
            symbol, 0,
            string, ZEND_MM_ALIGNED_SIZE(_ZSTR_STRUCT_SIZE(stack.len))) != SUCCESS) {
        free(string);
        return NULL;
    }
    
    return string;
}

static zend_always_inline zend_function* php_trace_get_function(php_trace_context_t *context, zend_function *symbol) {
    zend_function *function = zend_hash_index_find_ptr(&context->functions, (zend_ulong) symbol);
    zend_uchar     type;
    
    if (function) {
        if (function->common.scope && zend_hash_index_exists(&context->classes, (zend_ulong) function->common.scope)) {
            function->common.scope = zend_hash_index_find_ptr(
                &context->classes, (zend_ulong) function->common.scope);
        }
        return function;
    }
    
    if (php_trace_get_symbol(
            context->pid, 
            NULL, 
            symbol, 0,
            &type, sizeof(zend_uchar)) != SUCCESS) {
        return NULL;
    }
    
    function = calloc(1, PHP_TRACE_FUNCTION_SIZE(type));
    
    if (php_trace_get_symbol(
            context->pid, 
            NULL, 
            symbol, 0,
            function, PHP_TRACE_FUNCTION_SIZE(type)) != SUCCESS) {
        free(function);
        return NULL;
    }
    
    if (function->common.function_name) {
        function->common.function_name = php_trace_get_string(context, function->common.function_name);
    }
    
    if (function->type == ZEND_USER_FUNCTION) {
        if (function->op_array.filename) {
            function->op_array.filename = php_trace_get_string(context, function->op_array.filename);
        }
    }
    
    if (function->common.scope && zend_hash_index_exists(&context->classes, (zend_ulong) function->common.scope)) {
        function->common.scope = zend_hash_index_find_ptr(
            &context->classes, (zend_ulong) function->common.scope);
    }
    
    return zend_hash_index_add_ptr(&context->functions, (zend_ulong) symbol, function);
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

static zend_always_inline int php_trace_init_function_table(php_trace_context_t *context, HashTable *functions) {
    Bucket *bucket = functions->arData,
           *end    = bucket + functions->nNumUsed;
        
    while (bucket < end) {
        Bucket        copy;
        zend_function *function;
        zend_uchar    type;

        if (php_trace_get_symbol(
                context->pid, 
                NULL, 
                bucket, 0,
                &copy, sizeof(Bucket)) != SUCCESS) {
            fprintf(stderr, "failed to get bucket from function table\n");
            return FAILURE;
        }
        
        if (php_trace_get_symbol(
                context->pid, 
                NULL, 
                copy.val.value.ptr, 0,
                &type, sizeof(zend_uchar)) != SUCCESS) {
            fprintf(stderr, "failed to get function type from function\n");
            return FAILURE;
        }
        
        function = calloc(1, PHP_TRACE_FUNCTION_SIZE(type));
        
        if (php_trace_get_symbol(
                context->pid, 
                NULL, 
                copy.val.value.ptr, 0,
                function, PHP_TRACE_FUNCTION_SIZE(type)) != SUCCESS) {
            fprintf(stderr, "failed to get function from function table\n");
            return FAILURE;
        }
        
        if (function->common.function_name) {
            function->common.function_name = php_trace_get_string(context, function->common.function_name);
        }
        
        if (function->type == ZEND_USER_FUNCTION) {
            if (function->op_array.filename) {
                function->op_array.filename = php_trace_get_string(context, function->op_array.filename);
            }
        }
        
        zend_hash_index_add_ptr(&context->functions, (zend_ulong) copy.val.value.ptr, function);
        bucket++;
    }
    
    return SUCCESS;
}

static zend_always_inline int php_trace_context_init(php_trace_context_t *context) {
    zend_executor_globals executor;
    HashTable             functions;
    HashTable             classes;
    
    if (php_trace_attach(context) != SUCCESS) {
        fprintf(stderr, "failed to attach to %d\n", context->pid);
        return FAILURE;
    }
    
    if (php_trace_get_symbol(
            context->pid, 
            &context->symbols, 
            ZEND_STRL("executor_globals"), 
            &executor, sizeof(zend_executor_globals)) != SUCCESS) {
        fprintf(stderr, "failed to get executor address\n");
        return FAILURE;
    }
    
    if (php_trace_get_symbol(
            context->pid, 
            NULL, 
            executor.function_table, 0,
            &functions, sizeof(HashTable)) != SUCCESS) {
        fprintf(stderr, "failed to get functions from executor\n");
        return FAILURE;
    }
    
    zend_hash_init(
        &context->functions, 
        zend_hash_num_elements(&functions), 
        NULL, php_trace_context_functions_dtor, 1);
    
    php_trace_init_function_table(context, &functions);
    
    if (php_trace_get_symbol(
            context->pid, 
            NULL, 
            executor.class_table, 0,
            &classes, sizeof(HashTable)) != SUCCESS) {
        fprintf(stderr, "failed to get classes from executor\n");
        return FAILURE;
    }
    
    zend_hash_init(&context->classes, 
        zend_hash_num_elements(&classes), 
        NULL, php_trace_context_classes_dtor, 1);
    {
        Bucket *bucket = classes.arData,
               *end    = bucket + classes.nNumUsed;
        
        while (bucket < end) {
            Bucket            copy;
            zend_class_entry *class = calloc(1, sizeof(zend_class_entry));

            if (php_trace_get_symbol(
                    context->pid, 
                    NULL, 
                    bucket, 0,
                    &copy, sizeof(Bucket)) != SUCCESS) {
                fprintf(stderr, "failed to get bucket from class table\n");
                return FAILURE;
            }
            
            if (php_trace_get_symbol(
                    context->pid, 
                    NULL, 
                    copy.val.value.ptr, 0,
                    class, sizeof(zend_class_entry)) != SUCCESS) {
                fprintf(stderr, "failed to get class from class table\n");
                return FAILURE;
            }
            
            class->name = php_trace_get_string(context, class->name);
            
            php_trace_init_function_table(
                context, &class->function_table);
            
            zend_hash_index_add_ptr(
                &context->classes, (zend_ulong) copy.val.value.ptr, class);
            bucket++;
        }
    }
    
    if (php_trace_detach(context) != SUCCESS) {
        fprintf(stderr, 
            "failed to detach from %d\n", context->pid);
        return FAILURE;
    }
    
    return SUCCESS;
}

php_trace_action_t php_trace_frame_print(php_trace_context_t *context, zend_execute_data *frame, uint32_t depth, zend_function *function, zend_op *instruction) {
    uint32_t it = 1,
             end = depth;
    
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

int php_trace_main(php_trace_context_t *context, int argc, char **argv) {
    Dwfl* php_trace_dwfl = dwfl_begin(&php_trace_dwfl_callbacks);

    if (!php_trace_dwfl) {
        fprintf(stderr, 
            "couldn't initialize DWFL\n");
        return 1;
    }
    
    if (dwfl_linux_proc_report(php_trace_dwfl, context->pid) != SUCCESS) {
        fprintf(stderr, 
            "DWFL could not report on %d\n", context->pid);
        return 1;
    }
    
    dwfl_getmodules(php_trace_dwfl, php_trace_dwfl_get_module, context, 0);
    dwfl_report_end(php_trace_dwfl, NULL, NULL);
    dwfl_end(php_trace_dwfl);
    
    if (php_trace_context_init(context) != SUCCESS) {
        return 1;
    }
    
    if (context->onBegin) {
        context->onBegin(context);
    }
    
    do {
        zend_executor_globals  executor;
        zend_execute_data      frame, *fp;
        zend_function          *function;
        zend_op                instruction;
        zend_long              depth = 1;
        
        memset(&executor,    0, sizeof(zend_executor_globals));
        memset(&frame,       0, sizeof(zend_execute_data));
        memset(&instruction, 0, sizeof(zend_op));
        
        if (php_trace_attach(context) != SUCCESS) {
            fprintf(stderr, "failed to attach to %d\n", context->pid);
            break;
        }
    
        if (php_trace_get_symbol(
                context->pid, 
                &context->symbols, 
                ZEND_STRL("executor_globals"), 
                &executor, sizeof(zend_executor_globals)) != SUCCESS) {
            fprintf(stderr, "failed to get executor\n");
            break;
        }
        
        fp = executor.current_execute_data;
        
        if (context->onStackStart) {
            if (context->onStackStart(context) == PHP_TRACE_QUIT) {
                break;
            }
        }
        
        do {
            if (!fp || php_trace_get_symbol(
                    context->pid, 
                    NULL, 
                    fp, 0,
                    &frame, sizeof(zend_execute_data)) != SUCCESS) {
                context->samples--;
                break;
            }
            
            function = php_trace_get_function(context, frame.func);
            
            if (function && function->type == ZEND_USER_FUNCTION) {
                if (php_trace_get_symbol(
                        context->pid, 
                        NULL, 
                        (void*) frame.opline, 0,
                        &instruction, sizeof(zend_op)) != SUCCESS) {
                    fprintf(stderr, "failed to get instruction\n");
                    break;
                }
            }
            
            if (context->onFrame) {
                if (context->onFrame(context, &frame, depth, function, &instruction) == PHP_TRACE_STOP) {
                    break;
                }
            }
            
            if ((++depth > context->depth) && (context->depth > 0)) {
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
    
    zend_hash_destroy(&context->symbols);
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
