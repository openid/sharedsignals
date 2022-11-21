OPEN=$(word 1, $(wildcard /usr/bin/xdg-open /usr/bin/open /bin/echo))
SOURCES?=${wildcard *.xml}
TEXT=${SOURCES:.xml=.txt}
HTML=${SOURCES:.xml=.html}

text:	$(TEXT)
html:   $(HTML)

%.html: %.xml
	xml2rfc --html $^

%.txt:	%.xml
	python spanx_verb_to_quote.py $^ $^.quote
	xml2rfc -o $(subst .xml,.txt,$^) $^.quote
	rm $^.quote

%.xml: %.md
	kramdown-rfc2629 > $@ $^
