# SSF: Shared Signals Framework #

The goal of the [Shared Signals](http://openid.net/wg/sharedsignals/) Working Group is to enable the sharing of security events, state changes, and other signals between related and/or dependent systems in order to:

* Manage access to resources and enforce access control restrictions across distributed services operating in a dynamic environment.
* Prevent malicious actors from leveraging compromises of accounts, devices, services, endpoints, or other principals or resources to gain unauthorized access to additional systems or resources.
* Enable users, administrators, and service providers to coordinate in order to detect and respond to incidents.

## Current Development Drafts
The current drafts of the specifications under development are kept here:

| Specification            | HTML    | TXT    |
|--------------------------|---------|--------|
| Shared Signals Framework | [HTML](https://openid.github.io/sharedsignals/openid-sharedsignals-framework-1_0.html)| [TXT](https://openid.github.io/sharedsignals/openid-sharedsignals-framework-1_0.txt)|
| CAEP                     | [HTML](https://openid.github.io/sharedsignals/openid-caep-specification-1_0.html)| [TXT](https://openid.github.io/sharedsignals/openid-caep-specification-1_0.txt)|
| RISC                     | [HTML](https://openid.github.io/sharedsignals/openid-risc-profile-specification-1_0.html)| [TXT](https://openid.github.io/sharedsignals/openid-risc-profile-specification-1_0.txt)|



## Development

To change the spec, update one of the xml files and then run `make` as follows:

Assume you changed the file `foo.md`. To generate the `foo.html` file, you would run `make foo.html`

Similarly, to update the text file, you would run `make foo.txt`

Pay attention to errors generating the files and warnings about the document date. You should update the date to today's date.

In order to run `make` you need to:
1. install `xml2rfc` which can be done via pip: `pip install xml2rfc`
1. install `kramdown-rfc` which can be done via Ruby gems: `gem install kramdown-rfc`

**Note** The HTML and TXT files will not be uploaded to the repository. Running make only ensures that changes you made are not breaking the generation of the specifications output.
