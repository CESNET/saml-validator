# SAML-validator

**For more information, look at the [SAML-validator Wiki][] page.**

## Installation

If you would like to test *SAML-validator* which is a part of [MetaMan][], you can run it at [rr.cesnet.cz/saml-validator][]. Anyway, I recommend you to clone the repository to your own machine.

```bash
# mkdir /var/www/saml-validator/
# git clone https://github.com/JanOppolzer/saml-validator.git /var/www/saml-validator/
```

On Debian 9 (Stretch) you need a web server and a PHP processor with XML support:

```bash
# apt install apache2 php php-xml
```

You might prefer to disable directory listing by adding the following lines to your Apache configuration. Anyway, an `index.php` file is available, so if this one is loaded by default (most probably), you do not need to disable directory listing.

```apache
<Directory /var/www/saml-validator/>
    Options -Indexes
</Directory>
```

## Usage

There are three ways to validate your metadata:

1. Either specify a metadata URL (must be HTTPS address) or select a metadata file (must be an XML document) at the main page, i.e. `index.php`.
2. Supply a metadata URL (must be HTTPS address) as an HTTP GET variable `link` at `validate.php` file.
3. Supply a metadata file as the first argument to `validate-cli.sh` script in the shell.

[SAML-validator Wiki]: https://github.com/JanOppolzer/saml-validator/wiki
[MetaMan]: https://github.com/JanOppolzer/metaman
[rr.cesnet.cz/saml-validator]: https://rr.cesnet.cz/saml-validator/

