<?php

/**
 * SAML-validator [1] is a utility to validate SAML metadata for SAML Identity
 * Federation and cooperates nicely with a web-based metadata management system
 * Jagger [2].
 *
 * SAML-validator is written by Jan Oppolzer [3] from CESNET [4] and all the
 * validation checks ensure that metadata is compatible with the Czech
 * academic identity federation eduID.cz [5] as well as the testing federation
 * czTestFed [6].
 *
 * [1] https://github.com/JanOppolzer/saml-validator
 * [2] https://jagger.heanet.ie
 * [3] jan@oppolzer.cz
 * [4] https://www.cesnet.cz
 * [5] https://www.eduid.cz
 * [6] https://www.eduid.cz/cs/cztestfed/index
 *
 */

/**
 * Set Content-Type to text/xml.
 */
header("Content-Type: text/xml");

/**
 * Variables
 */
$TMP_DIRECTORY      = "tmp/";
$CRT_KEY_SIZE       = 2048;                     // certificate's public key size in bits
$CRT_VALIDITY       = 30;                       // certificate's validity in days
$REPUBLISH_TARGET   = "http://edugain.org/";
$EC_RS              = "http://refeds.org/category/research-and-scholarship";
$EC_COCO_1          = "http://www.geant.net/uri/dataprotection-code-of-conduct/v1";
$EC_SIRTFI          = "https://refeds.org/sirtfi";

/**
 * writeXML() function composes a resulting XML document.
 */
function writeXML($returncode, $message = null, $warning = null) {
    $xml = new XMLWriter();

    $xml->openURI("php://output");
    $xml->setIndent(true);
    $xml->setIndentString("  ");

    $xml->startDocument("1.0", "utf-8");
    $xml->startElement("validation");
    $xml->writeElement("returncode", $returncode);
    $xml->writeElement("message", $message);
    $xml->writeElement("warning", $warning);
    $xml->endElement();
    $xml->endDocument();

    $xml->flush();
}

/**
 * checkDependencies() checks for required PHP dependencies.
 */
function checkDependencies() {
    if(!extension_loaded("xmlwriter"))
        throw new Exception("XMLwritter support not available.");

    if(!extension_loaded("exif"))
        throw new Exception("Exif support not available.");

    if(!extension_loaded("gd"))
        throw new Exception("GD support not available.");
}

/**
 * checkTempDir() checks $TMP_DIRECTORY for existance and writtability.
 */
function checkTempDir($dir) {
    if(!file_exists($dir) || !is_dir($dir))
        throw new Exception(dirname(__FILE__) . "/" . $dir . " directory doesn't exists.");

    if(!is_writable($dir))
        throw new Exception(dirname(__FILE__) . "/" . $dir . " directory isn't writtable.");
}

/**
 * getMetadataURL() checks for proper URL address in $_GET["filename"].
 */
function getMetadataURL() {
    if(empty($_GET["filename"]))
        throw new Exception("No metadata URL defined using HTTP GET variable `filename`.");

    $filename = $_GET["filename"];
    if(!filter_var($filename, FILTER_VALIDATE_URL))
        throw new Exception("Invalid metadata URL supplied in HTTP GET variable `filename`.");
    elseif(!preg_match("/^https\:\/\//", $filename))
        throw new Exception("Metadata URL supplied in HTTP GET variable `filename` must be HTTPS.");
    else
        return $filename;
}

/**
 * getMetadataFile() fetches metadata.
 */
function getMetadataFile($url) {
    $metadata = file_get_contents($url);

    if(empty($metadata))
        throw new Exception("Metadata file has no content.");

    $file = $GLOBALS['TMP_DIRECTORY'] . time() . "-" . uniqid() . "-" . rand(1000, 9999) . ".xml";
    file_put_contents($file, $metadata);

    return $file;
}

/**
 * libxml_display_errors() returns libXML errors.
 */
// FIXME
function libxml_display_errors() {
    $errors = libxml_get_errors();
    $result = null;

    foreach($errors as $e)
        $result .= trim($e->message) . " ";

    return $result;

    libxml_clear_errors();
}

/**
 * createDOM() creates a DOM object.
 */
function createDOM($xml) {
    libxml_use_internal_errors(true);

    $dom = new DOMDocument();
    $dom->load($xml);

    if(!$dom->schemaValidate("xsd/saml-schema-metadata-2.0.xsd") or
       !$dom->schemaValidate("xsd/sstc-saml-metadata-ui-v1.0.xsd"))
        throw new Exception(libxml_display_errors());

    return $dom;
}

/**
 * createXPath() creates an XPath object.
 */
function createXPath($dom) {
    $xpath = new DOMXpath($dom);

    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $xpath->registerNameSpace("ds", "http://www.w3.org/2000/09/xmldsig#");
    $xpath->registerNameSpace("shibmd", "urn:mace:shibboleth:metadata:1.0");
    $xpath->registerNameSpace("mdui", "urn:oasis:names:tc:SAML:metadata:ui");
    $xpath->registerNameSpace("eduidmd", "http://eduid.cz/schema/metadata/1.0");
    $xpath->registerNameSpace("init", "urn:oasis:names:tc:SAML:profiles:SSO:request-init");
    $xpath->registerNameSpace("idpdisc", "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol");
    $xpath->registerNameSpace("mdattr", "urn:oasis:names:tc:SAML:metadata:attribute");
    $xpath->registerNameSpace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
    $xpath->registerNameSpace("remd", "http://refeds.org/metadata");

    return $xpath;
}

/**
 * getSkipCheck() checks for tests to be skipped in $_GET["skipCheck"].
 */
function getSkipCheck() {
    if(!empty($_GET["skipCheck"])) {
        $flags = array('flags' => FILTER_FLAG_STRIP_LOW |
                                  FILTER_FLAG_STRIP_HIGH |
                                  FILTER_FLAG_STRIP_BACKTICK);
        $skipCheck = filter_input(INPUT_GET, 'skipCheck', FILTER_SANITIZE_STRING, $flags);

        return explode(",", $skipCheck);
    }

    return array();
}

/**
 * isIDP() decides if an entity is an IdP or not.
 */
function isIDP($xpath) {
    if($xpath->query("/md:EntityDescriptor/md:IDPSSODescriptor")->length > 0)
        return true;
}

/**
 * checkHTTPS() validates that ALL URLs are HTTPS
 */
function checkHTTPS($xpath) {
    $URL = array();
    $result = array();

    # /md:EntityDescriptor[@entityID]
    $entityID = $xpath->query("/md:EntityDescriptor");
    $URL["entityID"] = $entityID->item(0)->getAttribute("entityID");

    # //mdui:UIInfo/mdui:Logo
    $Logo = $xpath->query("//mdui:UIInfo/mdui:Logo");
    for($i=0; $i<$Logo->length; $i++) {
        $URL["Logo".$i] = $Logo->item($i)->nodeValue;
    }

    # //md:ArtifactResolutionService
    $ArtifactResolutionService = $xpath->query("/md:EntityDescriptor//md:ArtifactResolutionService");
    for($i=0; $i<$ArtifactResolutionService->length; $i++) {
        $URL["ArtifactResolutionService".$i] = $ArtifactResolutionService->item($i)->getAttribute("Location");
    }

    # //md:SingleLogoutService
    $SingleLogoutService = $xpath->query("/md:EntityDescriptor//md:SingleLogoutService");
    for($i=0; $i<$SingleLogoutService->length; $i++) {
        $URL["SingleLogoutService".$i] = $SingleLogoutService->item($i)->getAttribute("Location");
    }

    # //md:SingleSignOnService
    $SingleSignOnService = $xpath->query("/md:EntityDescriptor//md:SingleSignOnService");
    for($i=0; $i<$SingleSignOnService->length; $i++) {
        $URL["SingleSignOnService".$i] = $SingleSignOnService->item($i)->getAttribute("Location");
    }

    # //md:AttributeService
    $AttributeService = $xpath->query("/md:EntityDescriptor/md:AttributeAuthorityDescriptor/md:AttributeService");
    for($i=0; $i<$AttributeService->length; $i++) {
        $URL["AttributeService".$i] = $AttributeService->item($i)->getAttribute("Location");
    }

    # //init:RequestInitiator
    $RequestInitiator = $xpath->query("/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/init:RequestInitiator");
    for($i=0; $i<$RequestInitiator->length; $i++) {
        $URL["RequestInitiator".$i] = $RequestInitiator->item($i)->getAttribute("Location");
    }

    # //idpdisc:DiscoveryResponse
    $DiscoveryResponse = $xpath->query("/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/idpdisc:DiscoveryResponse");
    for($i=0; $i<$DiscoveryResponse->length; $i++) {
        $URL["DiscoveryResponse".$i] = $DiscoveryResponse->item($i)->getAttribute("Location");
    }

    # //md:AssertionConsumerService
    $AssertionConsumerService = $xpath->query("/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService");
    for($i=0; $i<$AssertionConsumerService->length; $i++) {
        $URL["AssertionConsumerService".$i] = $AssertionConsumerService->item($i)->getAttribute("Location");
    }

    foreach($URL as $key => $value) {
        if(!preg_match("/https\:\/\//", $value)) {
            array_push($result, "HTTPS missing in $key.");
        }
    }

    return $result;
}

/**
 * checkRepublishRequest() validates republish requests to eduGAIN
 */
function checkRepublishRequest($xpath) {
    $result = array();

    $republishRequestIDP = $xpath->query("/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/eduidmd:RepublishRequest");
    $republishRequestSP  = $xpath->query("/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/eduidmd:RepublishRequest");
    $republishRequest    = $xpath->query("/md:EntityDescriptor/md:Extensions/eduidmd:RepublishRequest");
    $republishTarget     = $xpath->query("/md:EntityDescriptor/md:Extensions/eduidmd:RepublishRequest/eduidmd:RepublishTarget");

    if(($republishRequestSP->length > 0) or ($republishRequestIDP->length > 0)) {
        array_push($result, "RepublishRequest placed incorrectly.");
    } elseif($republishRequest->length > 0) {
        if($republishTarget->length > 0) {
            if(strcmp($GLOBALS['REPUBLISH_TARGET'], $republishTarget->item(0)->nodeValue) !== 0) {
                array_push($result, "RepublishRequest->RepublishTarget misconfigured.");
            }
        } else {
            array_push($result, "RepublishRequest->RepublishTarget missing.");
        }
    }

    return $result;
}

/**
 * checkURLaddress() checks element's URL address for existence and reachability.
 */
function checkURLaddress($element) {
    $result = false;

    foreach($element as $e) {
        @$file = file_get_contents($e->nodeValue);
        if($http_response_header === NULL)
            $result = $e->parentNode->nodeName . "->" . $e->nodeName . "/" . $e->getAttribute("xml:lang") . " couldn't be read (SSL error? Check www.ssllabs.com).";
        elseif(preg_match("/403|404|500/", $http_response_header[0]))
            $result = $e->parentNode->nodeName . "->" . $e->nodeName . "/" . $e->getAttribute("xml:lang") . " couldn't be read due to " . $http_response_header[0] . " return code.";
        elseif(!$file)
            $result = $e->parentNode->nodeName . "->" . $e->nodeName . "/" . $e->getAttribute("xml:lang") . " failed to load.";
    }

    return $result;
}

/**
 * checkUIInfo() validates //mdui:UIInfo element
 */
function checkUIInfo($xpath) {
    $result = array();

    if(isIDP($xpath)) {
        $SSODescriptor = 'IDPSSODescriptor';
    } else {
        $SSODescriptor = 'SPSSODescriptor';
    }

    $UIInfoDisplayNameCS        = $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="cs"]');
    $UIInfoDisplayNameEN        = $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]');
    $UIInfoDescriptionCS        = $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="cs"]');
    $UIInfoDescriptionEN        = $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="en"]');
    $UIInfoInformationURLCS     = $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:InformationURL[@xml:lang="cs"]');
    $UIInfoInformationURLEN     = $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:InformationURL[@xml:lang="en"]');
    $UIInfoLogo                 = $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:Logo');
    $UIInfoPrivacyStatementURLCS= $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL[@xml:lang="cs"]');
    $UIInfoPrivacyStatementURLEN= $xpath->query('/md:EntityDescriptor/md:'.$SSODescriptor.'/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL[@xml:lang="en"]');

    if($UIInfoDisplayNameCS->length !== 1)
       array_push($result, "$SSODescriptor" . "->UIInfo->DisplayName/cs missing.");
    if($UIInfoDisplayNameEN->length !== 1)
       array_push($result, "$SSODescriptor" . "->UIInfo->DisplayName/en missing.");
    if($UIInfoDescriptionCS->length !== 1)
       array_push($result, "$SSODescriptor" . "->UIInfo->Description/cs missing.");
    if($UIInfoDescriptionEN->length !== 1)
       array_push($result, "$SSODescriptor" . "->UIInfo->Description/en missing.");
    if($UIInfoInformationURLCS->length !== 1) {
       array_push($result, "$SSODescriptor" . "->UIInfo->InformationURL/cs missing.");
    } else {
        $r = checkURLaddress($UIInfoInformationURLCS);
        if($r) array_push($result, $r);
    }
    if($UIInfoInformationURLEN->length !== 1) {
        array_push($result, "$SSODescriptor" . "->UIInfo->InformationURL/en missing.");
    } else {
        $r = checkURLaddress($UIInfoInformationURLEN);
        if($r) array_push($result, $r);
    }
    if(isIDP($xpath)) {
       if($UIInfoLogo->length < 1) {
           array_push($result, "$SSODescriptor" . "->UIInfo->Logo missing.");
       } else {
           foreach($UIInfoLogo as $logo) {
               @$file = file_get_contents($logo->nodeValue);
               if($http_response_header === NULL) {
                   array_push($result, "Logo $logo->nodeValue could not be downloaded (SSL error? Check www.ssllabs.com).");
               } elseif(!$file) {
                   array_push($result, "Logo $logo->nodeValue does not exist.");
               } else {
                   if(exif_imagetype($logo->nodeValue)) {
                       $imagesize  = getimagesize($logo->nodeValue);
                       $img_width  = $imagesize[0];
                       $img_height = $imagesize[1];
                       $md_width   = $logo->getAttribute("width");
                       $md_height  = $logo->getAttribute("height");

                       if($img_width != $md_width) {
                            array_push($result, "Logo $logo->nodeValue has a different width ($img_width px) than defined in metadata ($md_width px).");
                       }
                       if($img_height != $md_height) {
                            array_push($result, "Logo $logo->nodeValue has a different height ($img_height px) than defined in metadata ($md_height px).");
                       }
                   }
                   if(!exif_imagetype($logo->nodeValue)) {
                       $doc = new DOMDocument();
                       $doc->load($logo->nodeValue);
                       if(strcmp($doc->documentElement->nodeName, 'svg') !== 0)
                           array_push($result, "Logo $logo->nodeValue is not an image.");
                   }
               }
           }
       }
    }
    if($UIInfoPrivacyStatementURLCS->length > 0) {
        $r = checkURLaddress($UIInfoPrivacyStatementURLCS);
        if($r) array_push($result, $r);
    }
    if($UIInfoPrivacyStatementURLEN->length > 0) {
        $r = checkURLaddress($UIInfoPrivacyStatementURLEN);
        if($r) array_push($result, $r);
    }

    return $result;
}

/**
 * checkCertificate() validates certificate's public key size and validity time
 */
function checkCertificate($xpath) {
    $certsInfo  = array();
    $result     = array();

    $certificates = $xpath->query("//ds:X509Certificate");

    if($certificates->length > 0) {
        $certificate_number = 1;
        foreach($certificates as $cert) {
            $X509Certificate = "-----BEGIN CERTIFICATE-----\n" . trim ($cert->nodeValue) . "\n-----END CERTIFICATE-----";
            $cert_info = openssl_x509_parse($X509Certificate, true);
            if(is_array($cert_info)) {
                $cert_validTo = date("Y-m-d", $cert_info["validTo_time_t"]);
                $cert_validFor = floor((strtotime($cert_validTo)-time ())/(60*60*24));
                $pub_key = openssl_pkey_get_details(openssl_pkey_get_public($X509Certificate));
                array_push($certsInfo, array($cert_validTo, $cert_validFor, $pub_key["bits"]));
            } else {
                array_push($result, "The certificate #$certificate_number is invalid.");
            }
            $certificate_number++;
        }
    } else {
        array_push($result, "No certificate found.");
    }

    $certsResults = array_fill(0, count($certsInfo), array_fill(0, 2, null));
    for($i=0; $i<count($certsInfo); $i++) {
        if($certsInfo[$i][2] < $GLOBALS["CRT_KEY_SIZE"]) {
            $certsResults[$i][0] = "Public key size must be at least " . $GLOBALS["CRT_KEY_SIZE"] . " bits. Yours is only " . $certsInfo[$i][2] . ".";
        }

        if($certsInfo[$i][1] < $GLOBALS["CRT_VALIDITY"]) {
            $certsResults[$i][1] = "Certificate must be valid at least for " . $GLOBALS["CRT_VALIDITY"] . " days. Yours is " . $certsInfo[$i][1] . ".";
        }
    }

    for($i=0; $i<count($certsResults); $i++) {
        if($i%2 === 0) {
            continue;
        }

        if(($certsResults[$i][0] !== null) || ($certsResults[$i][1] !== null)) {
            foreach($certsResults[$i] as $m) {
                array_push($result, $m);
            }
        }

        if($certsResults[$i][0] !== null) {
            foreach($certsResults[$i] as $m) {
                array_push($result, $m);
            }
        }
    }

    return $result;
}

/**
 * checkScope() validates the <Scope> of an IdP
 */
function checkScope($xpath) {
    $result = array();

    $resultIDP = $xpath->query("/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/shibmd:Scope");
    $resultAA  = $xpath->query("/md:EntityDescriptor/md:AttributeAuthorityDescriptor/md:Extensions/shibmd:Scope");

    if($resultIDP->length !== 1) {
        array_push($result, "Precisely 1 IDPSSODescriptor->Scope required.");
    }
    if($resultAA->length > 1) {
        array_push($result, "Either 0 or 1 AttributeAuthorityDescriptor->Scope allowed.");
    }

    return $result;
}

/**
 * checkScopeRegexp() validates 'regexp="false"' for <Scope> element.
 */
function checkScopeRegexp($xpath) {
    $result = array();

    $scopes = $xpath->query("//shibmd:Scope[@regexp]");

    $regexpValue = array();
    if($scopes->length > 0) {
        foreach($scopes as $s) {
            array_push($regexpValue, $s->getAttribute("regexp"));
        }
    }

    foreach($regexpValue as $regexp) {
        if(strcmp($regexp, "false") !== 0) {
            array_push($result, "Scope regexp must be \"false\".");
        }
    }

    return $result;
}

/**
 * checkScopeValue() validates that <Scope> value is a substring of
 * //EntityDescriptor[@entityID] and also in lowercase
 */
function checkScopeValue($xpath) {
    $result = array();

    $entityDescriptor = $xpath->query("/md:EntityDescriptor");
    $scopes = $xpath->query("//shibmd:Scope[@regexp]");

    $entityID = $entityDescriptor->item(0)->getAttribute("entityID");
    $pattern = '/https:\/\/([a-z0-9_\-\.]+)\/.*/';
    $replacement = '$1';
    $hostname = preg_replace($pattern, $replacement, $entityID);

    $scopeValue = array();
    if($scopes->length > 0) {
        foreach($scopes as $s) {
            array_push($scopeValue, $s->nodeValue);
        }
    }

    foreach($scopeValue as $scope) {
        if(preg_match("/$scope/", $hostname) !== 1) {
            array_push($result, "Scope value must be a lowercase substring of the entityID!");
        }
    }

    return $result;
}

/**
 * checkAttributeAuthorityDescriptor() validates AttributeAuthorityDescriptor[@protocolSupportEnumeration]
 */
function checkAttributeAuthorityDescriptor($xpath) {
    $result = array();

    $SAML2binding  = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    $SAML2protocol = "urn:oasis:names:tc:SAML:2.0:protocol";

    $AttributeAuthorityDescriptor = $xpath->query("/md:EntityDescriptor/md:AttributeAuthorityDescriptor");

    if($AttributeAuthorityDescriptor->length > 0) {
        $AttributeService = $xpath->query("/md:EntityDescriptor/md:AttributeAuthorityDescriptor/md:AttributeService");
        $protocols = $AttributeAuthorityDescriptor->item(0)->getAttribute("protocolSupportEnumeration");

        for($i=0; $i<$AttributeService->length; $i++) {
            if(strcmp($AttributeService->item($i)->getAttribute("Binding"), $SAML2binding) === 0) {
                if(!preg_match("/$SAML2protocol/", $protocols)) {
                    array_push($result, "SAML 2.0 binding requires SAML 2.0 token in AttributeAuthorityDescriptor[@protocolSupportEnumeration].");
                }
            }
        }

        if(preg_match("/$SAML2protocol/", $protocols)) {
            $tmpResult = $AttributeService->length;
            for($i=0; $i<$AttributeService->length; $i++) {
                if(strcmp($SAML2binding, $AttributeService->item($i)->getAttribute("Binding")) !== 0) {
                    $tmpResult--;
                }
            }
            if($tmpResult < 1) {
                    array_push($result, "SAML 2.0 token in AttributeAuthorityDescriptor[@protocolSupportEnumeration] requires SAML 2.0 binding.");
            }
        }
    }

    return $result;
}

/**
 * checkOrganization() validates that <Organization> element is present.
 */
function checkOrganization($xpath) {
    $result = array();

    $organization = $xpath->query("/md:EntityDescriptor/md:Organization");

    if($organization->length === 0)
        array_push($result, "<Organization> element missing.");
    else {
        $organizationNameCS         = $xpath->query("/md:EntityDescriptor/md:Organization/md:OrganizationName[@xml:lang='cs']");
        $organizationNameEN         = $xpath->query("/md:EntityDescriptor/md:Organization/md:OrganizationName[@xml:lang='en']");
        $organizationDisplayNameCS  = $xpath->query("/md:EntityDescriptor/md:Organization/md:OrganizationDisplayName[@xml:lang='cs']");
        $organizationDisplayNameEN  = $xpath->query("/md:EntityDescriptor/md:Organization/md:OrganizationDisplayName[@xml:lang='en']");
        $organizationURLCS          = $xpath->query("/md:EntityDescriptor/md:Organization/md:OrganizationURL[@xml:lang='cs']");
        $organizationURLEN          = $xpath->query("/md:EntityDescriptor/md:Organization/md:OrganizationURL[@xml:lang='en']");

        if($organizationNameCS->length === 0)
            array_push($result, "Organization->OrganizationName/cs missing.");
        if($organizationNameEN->length === 0)
            array_push($result, "Organization->OrganizationName/en missing.");
        if($organizationDisplayNameCS->length === 0)
            array_push($result, "Organization->OrganizationDisplayName/cs missing.");
        if($organizationDisplayNameEN->length === 0)
            array_push($result, "Organization->OrganizationDisplayName/en missing");
        if($organizationURLCS->length === 0) {
            array_push($result, "Organization->OrganizationURL/cs missing.");
        } else {
            $r = checkURLaddress($organizationURLCS);
            if($r) array_push($result, $r);
        }
        if($organizationURLEN->length === 0) {
            array_push($result, "Organization->OrganizationURL/en missing.");
        } else {
            $r = checkURLaddress($organizationURLEN);
            if($r) array_push($result, $r);
        }
    }

    return $result;
}

/**
 * checkContactPerson() validates that at least one <ContactPerson> contains contactType='technical' attribute.
 */
function checkContactPerson($xpath) {
    $result = array();

    $contactPerson          = $xpath->query("/md:EntityDescriptor/md:ContactPerson");
    $contactPersonTechnical = $xpath->query("/md:EntityDescriptor/md:ContactPerson[@contactType='technical']");

    if($contactPerson->length > 0) {
        $i = 1;
        foreach($contactPerson as $c) {
            $email = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "EmailAddress");

            if(!preg_match("/^mailto\:/", $email->item(0)->nodeValue))
                array_push($result, "ContactPerson (" . $i . ")->EmailAddress doesn't contain \"mailto:\" scheme.");

            $i++;
        }
    }

    if($contactPersonTechnical->length < 1)
        array_push($result, "ContactPerson/technical undefined.");
    else {
        $i = 1;
        foreach($contactPersonTechnical as $c) {
            $givenName = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "GivenName");
            $sn        = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "SurName");
            $email     = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "EmailAddress");

            if(empty($givenName->item(0)->nodeValue))
                array_push($result, "ContactPerson (" . $i . ")/technical->GivenName missing.");

            if(empty($sn->item(0)->nodeValue))
                array_push($result, "ContactPerson (" . $i . ")/technical->SurName missing.");

            if(empty($email->item(0)->nodeValue))
                array_push($result, "ContactPerson (" . $i . ")/technical->EmailAddress missing.");

            $i++;
        }
    }

    return $result;
}

/**
 * checkEC() validates SIRTFI and CoCo (v1 only so far) and warns if R&S (so we
 * can check the requirements).
 */
function checkEC($xpath) {
    $result = array();
    $warnings = array();

    $EC = $xpath->query("//mdattr:EntityAttributes/saml:Attribute");

    if($EC->length > 0) {

        $i = 1;
        foreach($EC as $category) {
            $value = $category->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue");
            #print_r($value->length);

            if($value->length > 0) {

                $j = 0;
                foreach($value as $v) {
                    #print_r($value->item($j)->nodeValue);

                    if(strcmp($value->item($j)->nodeValue, $GLOBALS["EC_RS"]) === 0) {
                        array_push($warnings, "R&S application.");
                    }

                    if(strcmp($value->item($j)->nodeValue, $GLOBALS["EC_COCO_1"]) === 0) {
                        array_push($warnings, "CoCo v1 application.");

                        if(!isIDP($xpath)) {
                            $PrivacyStatementURLCS = $xpath->query('/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL[@xml:lang="cs"]');
                            $PrivacyStatementURLEN = $xpath->query('/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL[@xml:lang="en"]');

                            if($PrivacyStatementURLCS->length === 0)
                                array_push($result, "$SSODescriptor" . "->UIInfo->PrivacyStatementURL/cs missing.");

                            if($PrivacyStatementURLEN->length === 0)
                                array_push($result, "$SSODescriptor" . "->UIInfo->PrivacyStatementURL/en missing.");
                        }

                    }

                    $j++;
                }
            }

            if(strcmp($value->item(0)->nodeValue, $GLOBALS["EC_SIRTFI"]) === 0) {
                $sirtfi_contact = $xpath->query("/md:EntityDescriptor/md:ContactPerson[@remd:contactType='http://refeds.org/metadata/contactType/security']");

                if($sirtfi_contact->length >= 1) {

                    foreach($sirtfi_contact as $c) {
                        $givenName  = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "GivenName");
                        $email      = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "EmailAddress");

                        if(empty($givenName->item(0)->nodeValue))
                            array_push($result, "SIRTFI contact missing GivenName.");

                        if(empty($email->item(0)->nodeValue))
                            array_push($result, "SIRTFI contact missing EmailAddress.");
                        else
                            array_push($warnings, "SIRTFI application (" . preg_replace('/mailto:/', '', $email->item(0)->nodeValue) . "). ");
                    }

                } else {
                    array_push($result, "SIRTFI defined, but contact missing.");
                }
            }
        }
    }

    return array($result, $warnings);
}

/**
 * mergeResults() merges individual check results.
 */
function mergeResults(&$results, $r) {
    $results = array_merge($results, $r);
    return $results;
}

/**
 * mergeWarnings() merges individual check warnings.
 */
function mergeWarnings(&$warnings, $w) {
    $warnings = array_merge($warnings, $w);
    return $warnings;
}

/**
 * generateResult() generates returncode and a possible error message.
 */
function generateResult($result) {
    $message = null;

    if(count($result) > 0) {
        $returncode = 2;

        foreach($result as $r)
            $message .= $r . " ";
    } else
        $returncode = 0;

    return array($returncode, $message);
}

/**
 * generateWarnings() generates a possible warning message.
 */
function generateWarnings($warnings) {
    $warning = null;

    foreach($warnings as $w) {
        $warning .= $w . " ";
    }

    return $warning;
}

/**
 * deleteMetadata() deletes metadata file.
 */
function deleteMetadata($file) {
    if(!unlink($file))
        throw new Exception("Metadata file couldn't be deleted.");
}

/* -------------------------------------------------- */

try {
    checkDependencies();
    checkTempDir($TMP_DIRECTORY);

    $url    = getMetadataURL();
    $file   = getMetadataFile($url);
    $dom    = createDOM($file);
    $xpath  = createXPath($dom);

    $skipCheck = getSkipCheck();

    $results = array();
    $warnings = array();

    mergeResults($results, checkHTTPS($xpath));
    mergeResults($results, checkRepublishRequest($xpath));
    mergeResults($results, checkUIInfo($xpath));
    mergeResults($results, checkCertificate($xpath));
    if(isIDP($xpath)) {
        mergeResults($results, checkScope($xpath));
        mergeResults($results, checkScopeRegexp($xpath));
        if(!in_array("checkScopeValue", $skipCheck)) {
            mergeResults($results, checkScopeValue($xpath));
        }
        mergeResults($results, checkAttributeAuthorityDescriptor($xpath));
    }
    mergeResults($results, checkOrganization($xpath));
    mergeResults($results, checkContactPerson($xpath));


    list($resultEC, $warningsEC) = checkEC($xpath);
    mergeResults($results, $resultEC);
    mergeWarnings($warnings, $warningsEC);

    list($returncode, $message) = generateResult($results);
    writeXML($returncode, $message, generateWarnings($warnings));

    deleteMetadata($file);
} catch(Throwable $t) {
    writeXML(2, "Caught Exception: " . $t->getMessage());
    exit(2);
} catch(Exception $e) {
    writeXML(2, "Caught Exception: " . $e->getMessage());
    exit(2);
}

