OPEN=$(word 1, $(wildcard /usr/bin/xdg-open /usr/bin/open /bin/echo))
SOURCES?=${wildcard *.xml */*.xml}
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
	@ make SSF_1.0/openid-sharedsignals-framework-1_0.xml
	@ make CAEP_1.0/openid-caep-1_0.xml
	@ make SSF_1.0/openid-sharedsignals-framework-1_0.html
	@ make SSF_1.0/openid-sharedsignals-framework-1_0.txt
	@ make RISC_1.0/openid-risc-1_0.html
	@ make RISC_1.0/openid-risc-1_0.txt
	@ make CAEP_1.0/openid-caep-1_0.html
	@ make CAEP_1.0/openid-caep-1_0.txt

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
	@ cp SSF_1.0/openid-sharedsignals-framework-1_0.txt ../publication/sharedsignals/openid-sharedsignals-framework-1_0-final.txt
	@ cp SSF_1.0/openid-sharedsignals-framework-1_0.html ../publication/sharedsignals/openid-sharedsignals-framework-1_0-final.html
	@ cp SSF_1.0/openid-sharedsignals-framework-1_0.md ../publication/sharedsignals/openid-sharedsignals-framework-1_0-final.md
	@ cp RISC_1.0/openid-risc-1_0.html ../publication/sharedsignals/openid-risc-1_0-final.html
	@ cp RISC_1.0/openid-risc-1_0.xml ../publication/sharedsignals/openid-risc-1_0-final.xml
	@ cp RISC_1.0/openid-risc-1_0.txt ../publication/sharedsignals/openid-risc-1_0-final.txt
	@ cp CAEP_1.0/openid-caep-1_0.txt ../publication/sharedsignals/openid-caep-1_0-final.txt
	@ cp CAEP_1.0/openid-caep-1_0.html ../publication/sharedsignals/openid-caep-1_0-final.html
	@ cp CAEP_1.0/openid-caep-1_0.md ../publication/sharedsignals/openid-caep-1_0-final.md
	@ cp openid-caep-interoperability-profile-1_0.md ../publication/sharedsignals/openid-caep-interoperability-profile-1_0-01.md
	@ cp openid-caep-interoperability-profile-1_0.xml ../publication/sharedsignals/openid-caep-interoperability-profile-1_0-01.xml
	@ cp openid-caep-interoperability-profile-1_0.html ../publication/sharedsignals/openid-caep-interoperability-profile-1_0-01.html
	@ cp openid-caep-interoperability-profile-1_0.txt ../publication/sharedsignals/openid-caep-interoperability-profile-1_0-01.txt
