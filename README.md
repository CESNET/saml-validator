# SAML-validator
SAML-validator is a tool to validate SAML metadata for [eduID.cz][] federation.

## Available validator
The following validations/checks are available:

  * validity against `saml-schema-metadata-2.0.xsd` XML schema
  * `<ds:X509Certificate>` element contains valid certificate with defined public key size
  * for IdPs, `<shimdb:Scope>` is required within both `<md:IDPSSODescriptor>` and `<md:AttributeAuthorityDescriptor>` elements
  * `regexp` attribute of `<shibmd:Scope>` element is set to `false`
  * `<shibmd:Scope>` element contains substring `/md:EntityDescriptor[@entityID]`
  * `<mdui:UIInfo>` element (with other elements inside -- `<mdui:DisplayName>`, `<mdui:Description>`, `<mdui:InformationURL>` and `<mdui:Logo>` (for IdPs)) present
  * `<md:Organization>` element present
  * at least one `<md:ContactPerson>` element with `contactType` attribute equal to `technical`
  * all "endpoints" and `entityID` must be HTTPS
  * `<eduidmd:RepublishRequest>` for eduGAIN export

## Installation
If you would like to test SAML-validator, say, in your [JAGGER][] instance or elsewhere, you can run it from my site ([snotra-saml-validator][]). However, this machine might not be up 24/7 and the code might be broken as this machine is intended for developing. You have been warned. Thus, you should clone the SAML-validator repository to your machine.

```bash
$ mkdir /var/www/saml-validator/
$ git clone https://github.com/JanOppolzer/saml-validator.git /var/www/saml-validator/
```

On Debian 9 (Stretch) you need a web server and a PHP processor with XML support:

```bash
$ apt install apache2 php php-xml
```

A temporary directory owned by the user running web server for downloading metadata to validate is required:

```bash
$ mkdir /var/www/saml-validator/tmp
$ chown www-data:www-data /var/www/saml-validator/tmp
```

You might prefer to disable directory listing by adding the following lines to your Apache configuration. Anyway, an `index.html` file is available, so if this one is loaded by default (most probably), you do not need to disable directory listing.

```apache
<Directory /var/www/saml-validator/>
    Options -Indexes
</Directory>
```

[eduID.cz]: http://www.eduid.cz/
[JAGGER]: http://jagger.heanet.ie/
[snotra-saml-validator]: https://snotra.cesnet.cz/~jop/saml-validator/

