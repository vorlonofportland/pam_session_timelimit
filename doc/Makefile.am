EXTRA_DISTS = pam_session_timelimit.8.xml
CLEANFILES  = pam_session_timelimit.8

man8_MANS = $(CLEANFILES)

%.8: %.8.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet $(top_srcdir)/doc/custom-man.xsl $<
