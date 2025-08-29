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

propose:
	@ cp openid-sharedsignals-framework-1_0.txt ../publication/sharedsignals/openid-sharedsignals-framework-1_0.txt
	@ cp openid-sharedsignals-framework-1_0.html ../publication/sharedsignals/openid-sharedsignals-framework-1_0.html
	@ cp openid-sharedsignals-framework-1_0.md ../publication/sharedsignals/openid-sharedsignals-framework-1_0.md
	@ cp openid-risc-1_0.html ../publication/sharedsignals/openid-risc-1_0.html
	@ cp openid-risc-1_0.xml ../publication/sharedsignals/openid-risc-1_0.xml
	@ cp openid-risc-1_0.txt ../publication/sharedsignals/openid-risc-1_0.txt
	@ cp openid-caep-1_0.txt ../publication/sharedsignals/openid-caep-1_0.txt
	@ cp openid-caep-1_0.html ../publication/sharedsignals/openid-caep-1_0.html
	@ cp openid-caep-1_0.md ../publication/sharedsignals/openid-caep-1_0.md