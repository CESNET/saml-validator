# SAML-validator

**For more information, look at the [SAML-validator Wiki][] page.**

## Installation
If you would like to test SAML-validator, say, in your [JAGGER][] instance or elsewhere, you can run it from my site ([snotra-saml-validator][]). However, this machine might not be up 24/7 and the code might be broken as this machine is intended for developing. You have been warned. Thus, you should clone the SAML-validator repository to your machine.

```bash
$ mkdir /var/www/saml-validator/
$ git clone https://github.com/JanOppolzer/saml-validator.git /var/www/saml-validator/
```

For SAML-validator to work, you need a temporary directory defined by a $TMP\_DIRECTORY variable (default value is `tmp/`) writtable by the web-server user (`www-data` in Debian). It is used for storing metadata to validate:
```bash
$ mkdir /var/www/saml-validator/tmp/
$ chown www-data:www-data /var/www/saml-validator/tmp/
```

On Debian 9 (Stretch) you need a web server and a PHP processor with XML support:

```bash
$ apt install apache2 php php-xml
```

You might prefer to disable directory listing by adding the following lines to your Apache configuration. Anyway, an `index.php` file is available, so if this one is loaded by default (most probably), you do not need to disable directory listing.

```apache
<Directory /var/www/saml-validator/>
    Options -Indexes
</Directory>
```

[SAML-validator Wiki]: https://github.com/JanOppolzer/saml-validator/wiki
[JAGGER]: http://jagger.heanet.ie/
[snotra-saml-validator]: https://snotra.cesnet.cz/~jop/saml-validator/

