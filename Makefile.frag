trace: $(BUILD_TRACE_BINARY)

$(BUILD_TRACE_BINARY): $(PHP_GLOBAL_OBJS) $(PHP_BINARY_OBJS) $(PHP_TRACE_OBJS)
	$(BUILD_TRACE_BIN)

install-trace: $(BUILD_TRACE_BINARY)
	@echo "Installing trace binary:          $(INSTALL_ROOT)$(bindir)/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(bindir)
	@$(INSTALL) -m 0755 $(BUILD_TRACE_BINARY) $(INSTALL_ROOT)$(bindir)/$(program_prefix)php-trace$(program_suffix)$(EXEEXT)
	@echo "Installing trace API:             $(INSTALL_ROOT)$(phpincludedir)/sapi/trace"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(phpincludedir)/sapi/trace
	@$(INSTALL) -m 0666 $(BUILD_TRACE_API)   $(INSTALL_ROOT)$(phpincludedir)/sapi/trace/php_trace.h
