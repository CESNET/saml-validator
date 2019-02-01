# SAML-validator

**For more information, look at the [SAML-validator Wiki][] page.**

## Installation
If you would like to test *SAML-validator*, say, in your instance of [MetaMan][], [Jagger][] or anything else, you can run it at [rr.cesnet.cz/saml-validator][]. Anyway, I recommend you to clone the repository to your own machine.

```bash
$ mkdir /var/www/saml-validator/
$ git clone https://github.com/JanOppolzer/saml-validator.git /var/www/saml-validator/
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
[MetaMan]: https://github.com/JanOppolzer/metaman
[Jagger]: http://jagger.heanet.ie/
[rr.cesnet.cz/saml-validator]: https://rr.cesnet.cz/saml-validator/

