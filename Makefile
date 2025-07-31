OPEN=$(word 1, $(wildcard /usr/bin/xdg-open /usr/bin/open /bin/echo))
SOURCES?=${wildcard *.xml}
TEXT=${SOURCES:.xml=.txt}
HTML=${SOURCES:.xml=.html}

text:	$(TEXT)
html:   $(HTML)

%.html: %.xml
	xml2rfc --html $^

%.txt:	%.xml
	xml2rfc $^

%.xml: %.md
	kramdown-rfc2629 > $@ $^

all:
	@ make openid-sharedsignals-framework-1_0.xml
	@ make openid-sharedsignals-framework-1_0.html
	@ make openid-sharedsignals-framework-1_0.txt
	@ make openid-risc-1_0.html
	@ make openid-risc-1_0.txt
	@ make openid-caep-1_0.xml
	@ make openid-caep-1_0.html
	@ make openid-caep-1_0.txt
