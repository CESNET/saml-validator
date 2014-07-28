# SAML-Validators
XML Schemas to validate SAML metadata in [eduID.cz][] federation

## Available validators
For now, there are following validators available:

  * tech-c
  * uiinfo
  * endpoints-entityID
  * organization
  * republish-target
  * certificate

A few other validators are currently being rewritten and tweaked in order to be incorporated into SAML-Validators very soon.

## Installation
If you would like to test SAML-Validators, say, in your [JAGGER][] instance or elsewhere, you can run it from my site ([devnull-saml-validators][]). However, this site might not be up 24/7, you have been warned. Thus, you should clone the SAML-Validators repository to your machine.

```bash
$ mkdir /var/www/saml-validators/
$ git clone https://github.com/JanOppolzer/saml-validators.git /var/www/saml-validators/
```





[eduID.cz]: http://www.eduid.cz/
[JAGGER]: http://jagger.heanet.ie/
[devnull-saml-validators]: https://devnull.cesnet.cz/saml-validators/

