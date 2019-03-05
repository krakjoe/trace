trace: $(BUILD_TRACE_BINARY)

$(BUILD_TRACE_BINARY): $(PHP_GLOBAL_OBJS) $(PHP_BINARY_OBJS) $(PHP_TRACE_OBJS)
	$(BUILD_TRACE_BIN)

install-trace: $(BUILD_TRACE_BINARY)
	@echo "Installing trace binary:         $(INSTALL_ROOT)$(bindir)/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(bindir)
	@$(mkinstalldirs) $(INSTALL_ROOT)$(localstatedir)/log
	@$(mkinstalldirs) $(INSTALL_ROOT)$(localstatedir)/run
	@$(INSTALL) -m 0755 $(BUILD_BINARY) $(INSTALL_ROOT)$(bindir)/$(program_prefix)trace$(program_suffix)$(EXEEXT)
	@echo "Installing trace man page:       $(INSTALL_ROOT)$(mandir)/man1/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(mandir)/man1
	@$(INSTALL_DATA) sapi/trace/trace.1 $(INSTALL_ROOT)$(mandir)/man1/$(program_prefix)trace$(program_suffix).1
