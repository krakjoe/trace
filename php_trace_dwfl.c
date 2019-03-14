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

#ifndef HAVE_PHP_TRACE_DWFL
#define HAVE_PHP_TRACE_DWFL

#include <php_trace.h>

#include <libelf.h>
#include <elfutils/libdwfl.h>

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
            
            if (header.sh_type == SHT_SYMTAB ||
                header.sh_type == SHT_DYNSYM) {
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

int php_trace_dwfl_init(php_trace_context_t *context) {
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
#endif
