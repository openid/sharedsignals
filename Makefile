OPEN=$(word 1, $(wildcard /usr/bin/xdg-open /usr/bin/open /bin/echo))
SOURCES?=${wildcard *.xml 1.0/*.xml 1.1/*.xml}
TEXT=${SOURCES:.xml=.txt}
HTML=${SOURCES:.xml=.html}

text:	$(TEXT)
html:   $(HTML)

%.html: %.xml
	xml2rfc --html $^ -o $@

%.txt:	%.xml
	xml2rfc $^ -o $@

%.xml: %.md
	kramdown-rfc2629 > $@ $^

all:
	@ make 1.0/openid-sharedsignals-framework-1_0.xml
	@ make 1.0/openid-caep-1_0.xml
	@ make 1.0/openid-sharedsignals-framework-1_0.html
	@ make 1.0/openid-sharedsignals-framework-1_0.txt
	@ make 1.0/openid-risc-1_0.html
	@ make 1.0/openid-risc-1_0.txt
	@ make 1.0/openid-caep-1_0.html
	@ make 1.0/openid-caep-1_0.txt

	@ make 1.1/openid-sharedsignals-framework-1_1.xml
	@ make 1.1/openid-caep-1_1.xml
	@ make 1.1/openid-sharedsignals-framework-1_1.html
	@ make 1.1/openid-sharedsignals-framework-1_1.txt
	@ make 1.1/openid-risc-1_1.html
	@ make 1.1/openid-risc-1_1.txt
	@ make 1.1/openid-caep-1_1.html
	@ make 1.1/openid-caep-1_1.txt

	@ make openid-caep-interoperability-profile-1_0.xml
	@ make openid-caep-interoperability-profile-1_0.html
	@ make openid-caep-interoperability-profile-1_0.txt


propose:
	@ cp 1.0/openid-sharedsignals-framework-1_0.txt ../publication/sharedsignals/openid-sharedsignals-framework-1_0-final.txt
	@ cp 1.0/openid-sharedsignals-framework-1_0.html ../publication/sharedsignals/openid-sharedsignals-framework-1_0-final.html
	@ cp 1.0/openid-sharedsignals-framework-1_0.md ../publication/sharedsignals/openid-sharedsignals-framework-1_0-final.md
	@ cp 1.0/openid-risc-1_0.html ../publication/sharedsignals/openid-risc-1_0-final.html
	@ cp 1.0/openid-risc-1_0.xml ../publication/sharedsignals/openid-risc-1_0-final.xml
	@ cp 1.0/openid-risc-1_0.txt ../publication/sharedsignals/openid-risc-1_0-final.txt
	@ cp 1.0/openid-caep-1_0.txt ../publication/sharedsignals/openid-caep-1_0-final.txt
	@ cp 1.0/openid-caep-1_0.html ../publication/sharedsignals/openid-caep-1_0-final.html
	@ cp 1.0/openid-caep-1_0.md ../publication/sharedsignals/openid-caep-1_0-final.md
	@ cp openid-caep-interoperability-profile-1_0.md ../publication/sharedsignals/openid-caep-interoperability-profile-1_0-01.md
	@ cp openid-caep-interoperability-profile-1_0.xml ../publication/sharedsignals/openid-caep-interoperability-profile-1_0-01.xml
	@ cp openid-caep-interoperability-profile-1_0.html ../publication/sharedsignals/openid-caep-interoperability-profile-1_0-01.html
	@ cp openid-caep-interoperability-profile-1_0.txt ../publication/sharedsignals/openid-caep-interoperability-profile-1_0-01.txt
