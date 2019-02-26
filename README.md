# SAML-validator

**For more information, look at the [SAML-validator Wiki][] page.**

## Installation

If you would like to test *SAML-validator* which is a part of [MetaMan][], you can run it at [validator.eduid.cz][]. Anyway, I recommend you to clone the repository to your own machine.

At [CESNET][], we run *SAML-validator* on Ubuntu 18.04 LTS (Bionic Beaver).

You need a web server (e.g. Apache) and a PHP processor with GD and XML support:

```bash
# apt install apache2 php php-gd php-xml
```

```bash
# mkdir /var/www/saml-validator/
# git clone https://github.com/CESNET/saml-validator.git /var/www/saml-validator/
```

You might want to deny access to `.git` directory. To do that, add the following lines to your Apache configuration:

```apache
# Deny access to `.git` directory inside DocumentRoot
RedirectMatch 404 /\.git
```

## Usage

There are three ways to validate your metadata:

1. Either specify a metadata URL (must be HTTPS address) or select a metadata file (must be an XML document) at the main page, i.e. `index.php`.
2. Supply a metadata URL (must be HTTPS address) as an HTTP GET variable `link` at `validate.php` file.
3. Supply a metadata file either as the first argument or as an standard input to `validate-cli.sh` script in the shell.

[SAML-validator Wiki]: https://github.com/JanOppolzer/saml-validator/wiki
[MetaMan]: https://github.com/JanOppolzer/metaman
[validator.eduid.cz]: https://validator.eduid.cz
[CESNET]: https://www.cesnet.cz

