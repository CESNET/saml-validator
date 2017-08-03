# SAML-Validator
XML Schemas to validate SAML metadata in [eduID.cz][] federation.

## Available validator
For now, there are the following validations available:

  * tech-c
  * uiinfo
  * endpoints-entityID
  * organization
  * republish-target
  * certificate
  * certificate-check

A few other validators are currently being rewritten and tweaked in order to be incorporated into SAML-Validator very soon.

## Installation
If you would like to test SAML-Validator, say, in your [JAGGER][] instance or elsewhere, you can run it from my site ([devnull-saml-validator][]). However, this site might not be up 24/7 and the code might be broken as this machine is intended for developing, you have been warned. Thus, you should clone the SAML-Validator repository to your machine.

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

You might prefer to disable directory listing by adding the following lines to your Apache configuration.

```apache
<Directory /var/www/saml-validator/>
    Options -Indexes
</Directory>
```

## Requirements
[xsd-validator][] is required. Install it into `xsd-validator/` subdirectory of the downloaded repository or edit `$XSD_VALIDATOR` variable in `validator.php` file accordingly.

```bash
$ cd /var/www/saml-validator/
$ git clone https://github.com/amouat/xsd-validator.git
```

To run [xsd-validator][], Java is required:

```bash
$ apt install openjdk-8-jre-headless
```


[eduID.cz]: http://www.eduid.cz/
[JAGGER]: http://jagger.heanet.ie/
[devnull-saml-validator]: https://devnull.cesnet.cz/saml-validator/
[xsd-validator]: https://github.com/amouat/xsd-validator/

