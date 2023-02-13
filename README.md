# SSF: Shared Signals Framework #

The goal of the [Shared Signals](http://openid.net/wg/sharedsignals/) Working Group is to enable the sharing of security events, state changes, and other signals between related and/or dependent systems in order to:

* Manage access to resources and enforce access control restrictions across distributed services operating in a dynamic environment.
* Prevent malicious actors from leveraging compromises of accounts, devices, services, endpoints, or other principals or resources to gain unauthorized access to additional systems or resources.
* Enable users, administrators, and service providers to coordinate in order to detect and respond to incidents.

## Development

To change the spec, update one of the xml files and then run `make` as follows:

Assume you changed the file `foo.md`. To generate the `foo.html` file, you would run `make foo.html`

Similarly, to update the text file, you would run `make foo.txt`

Pay attention to errors generating the files and warnings about the document date. You should update the date to today's date.

In order to run `make` you need to install `xml2rfc` which can be done via pip: `pip install xml2rfc`
