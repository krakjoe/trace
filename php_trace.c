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
#include <signal.h>

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
    {'s', 0, "stack"},
    {99,  0, "with-array-elements"},
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

zend_string* php_trace_get_string(php_trace_context_t *context, zend_string *symbol) {
    zend_string  *string;
    size_t        len;
    
    /* TODO cache strings based on hval ? */
    
    if (php_trace_get_symbol(
            context, 
            ((char*)symbol) + XtOffsetOf(zend_string, len),
            &len, sizeof(size_t)) != SUCCESS) {
        return NULL;
    }
    
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
        heap->common.function_name = php_trace_get_string(context, heap->common.function_name);
    }
    
    if (ZEND_USER_CODE(type)) {
        if (heap->op_array.filename) {
            heap->op_array.filename = php_trace_get_string(context, heap->op_array.filename);
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
                    vars[var] = php_trace_get_string(context, vars[var]);
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
				"           -d --depth      <int> Maximum stack depth       (default 64)\n"
				"           -m --max        <int> Maximum stack traces      (default unlimited)\n"
				"           -f --frequency  <int> Frequency of collection   (default 1000)\n"
				"Flags:\n"
				"           -s --stack                             Copy variables on stack from frame\n"
				"              --with-array-elements               Copy array elements\n"
				"Example Usage:\n"
				"%s -p 1337 -d1         - trace process 1337 generating traces with a single frame\n"
				"%s -p 1337 -d128 -m100 - trace process 1337 generating traces 128 frames deep stopping at 100 traces\n"
				, prog, prog, prog);
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

php_trace_action_result_t php_trace_begin(php_trace_context_t *context) {
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

    return PHP_TRACE_OK;
}

php_trace_action_result_t php_trace_stack_start(php_trace_context_t *context) {
    if (php_trace_attach(context) != SUCCESS) {
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
        if (!Z_COUNTED_P(it)) {
            it++;
            continue;
        }
        
        switch (Z_TYPE_P(it)) {
            case IS_STRING: {
                zend_string *str = php_trace_get_string(context, Z_STR_P(it));
                
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
                                bit->key = php_trace_get_string(context, bit->key);
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

static zend_always_inline void php_trace_zval_dtor(php_trace_context_t *context, zval *argv, uint32_t argc) {
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

static void php_trace_interrupt(int signum, siginfo_t *info, void *ucontext) {
    php_trace_context.interrupted = 1;
}

static zend_always_inline void php_trace_signal(int signo, void *handler) {
    struct sigaction sa;
    
    memset(&sa, 0, sizeof(struct sigaction));
    
    sa.sa_sigaction = handler;
    sa.sa_flags     = SA_SIGINFO;
    
    sigemptyset(&sa.sa_mask);
    
    sigaction(signo,  &sa, NULL);
}

int php_trace_main(php_trace_context_t *context, int argc, char **argv) {
    php_trace_signal(SIGINT,  php_trace_interrupt);
    
    if (context->onBegin) {
        if (context->onBegin(context) == PHP_TRACE_QUIT) {
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

int main(int argc, char **argv) {
    char *php_trace_optarg = NULL;
    int   php_trace_optind = 1,
          php_trace_optcur = 0;
    
    while ((php_trace_optcur = php_getopt(argc, argv, php_trace_options, &php_trace_optarg, &php_trace_optind, 0, 2)) != -1) {
        switch (php_trace_optcur) {
            case 'p': php_trace_context.pid   =  (pid_t) strtol(php_trace_optarg, NULL, 10); break;
            case 'm': php_trace_context.max   =  strtoul(php_trace_optarg, NULL, 10);        break;
            case 'd': php_trace_context.depth =  strtoul(php_trace_optarg, NULL, 10);        break;
            case 'f': php_trace_context.freq  =  strtoul(php_trace_optarg, NULL, 10);        break;
            case 's': php_trace_context.stack =  1;                                          break;
    
            case 99: php_trace_context.arData =  1;                                          break;
                                            
            case 'h': {
                php_trace_usage(argv[0]);
                return 0;
            } break;
            
            default:
                break;
        }
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

    return php_trace_main(&php_trace_context, argc, argv);
}
#endif
