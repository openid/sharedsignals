OPEN=$(word 1, $(wildcard /usr/bin/xdg-open /usr/bin/open /bin/echo))
SOURCES?=${wildcard *.xml}
TEXT=${SOURCES:.xml=.txt}
HTML=${SOURCES:.xml=.html}

text:	$(TEXT)
html:   $(HTML)

%.html: %.xml
	xml2rfc --html $<
	$(OPEN) $@

%.txt:	%.xml
	xml2rfc  $< $@
	$(OPEN) $@

%.xml: %.md
	kramdown-rfc2629 > $@ $^
