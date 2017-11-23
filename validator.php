<?php

header ("Content-Type: text/xml");

error_reporting ( E_ALL );
ini_set ('display_errors', 1);

/*
 * Download and validate metadata from JAGGER [1].
 *
 * Metadata URL has to be passed via HTTP GET variable called `filename'
 * defined in Federation Validators settings (JAGGER). Then, metadata is saved
 * as a XML file `ENCODED_ENTITYID'.xml (ENCODED_ENTITYID is generated
 * automatically by JAGGER) in `tmp/' subdirectory which must exist and be
 * writable by the user running web server. After validation process is
 * finished, the temporary XML file with metadata is deleted.
 *
 * SAML-validators is written by Jan Oppolzer [2] from CESNET [3] and can be
 * obtained from GitHub repository [4].
 *
 * [1] http://jagger.heanet.ie/
 * [2] jan.oppolzer@cesnet.cz
 * [3] https://www.cesnet.cz/
 * [4] https://github.com/JanOppolzer/saml-validator/
 *
 */

/* variable definitions
 */
$KEY_SIZE               = 2048; # bits
$CERTIFICATE_VALIDITY   = 30;   # days
$REPUBLISH_TARGET       = "http://edugain.org/";
$TMP_DIRECTORY          = "tmp/";

/* writeXML() function to produce XML output
 */
function writeXML($returncode, $message = null) {
    $xml = new XMLWriter();
    $xml->openURI("php://output");
    $xml->startDocument("1.0", "utf-8");
    $xml->setIndent(true);
    $xml->setIndentString("    ");
    $xml->startElement("validation");
    $xml->writeElement("returncode", $returncode);
    $xml->writeElement("message", $message);
    $xml->endElement();
    $xml->endDocument();
    $xml->flush();
}

/* filterResult() returns $returncode and $message variables
 */
function filterResult($validations) {
    $returncode = -1;
    $message    = null;

    foreach($validations as $validation) {
        $returncode = max($returncode, $validation[0]);
        $message .= $validation[1];
    }

    return array($returncode, $message);
}

/* isIDP function returns true in case $metadata is IdP
 */
function isIDP ($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $result = $xpath->query("/md:EntityDescriptor/md:IDPSSODescriptor");

    if ($result->length > 0) {
        return true;
    }
}

/* generates returncode and a warning/error message on the basis of $messages
 */
function generateResult($messages) {
    $message = "";
    if(count($messages) > 0) {
        $returncode = 2;
        foreach($messages as $m) {
            $message .= $m . " ";
        }
    } else {
        $returncode = 0;
    }

    return array($returncode, $message);
}

/* returns a string containing XML errors produced by libxml
 */
function libxml_display_errors() {
    $errors = libxml_get_errors();
    $return = null;
    foreach($errors as $error) {
        $return .= trim($error->message) . " ";
    }
    return $return;
    libxml_clear_errors();
}

/* validation function: validates the document agains XSD
 */
function validateSAML($metadata) {
    libxml_use_internal_errors(true);
    $xml = new DOMDocument();
    @$xml->load($metadata);
    if(!@$xml->schemaValidate('xsd/saml-schema-metadata-2.0.xsd') or
       !@$xml->schemaValidate('xsd/sstc-saml-metadata-ui-v1.0.xsd')) {
        $returncode = 2;
        $message    = libxml_display_errors();
    } else {
        $returncode = 0;
        $message    = "";
    }

    return array($returncode, $message);
}

/* validation function (certificate's public key size and validity)
 */
function certificateCheck($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("ds", "http://www.w3.org/2000/09/xmldsig#");
    $certificates = $xpath->query("//ds:X509Certificate");
    $certsInfo = array();
    $messages = array();

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
                array_push($messages, "The certificate #$certificate_number is invalid.");
            }
            $certificate_number++;
        }
    } else {
        array_push($messages, "No certificate found.");
    }

    $certsResults = array_fill(0, count($certsInfo), array_fill(0, 2, null));
    for($i=0; $i<count($certsInfo); $i++) {
        if($certsInfo[$i][2] < $GLOBALS["KEY_SIZE"]) {
            $certsResults[$i][0] = "Public key size must be at least " . $GLOBALS["KEY_SIZE"] . " bits. Yours is only " . $certsInfo[$i][2] . ".";
        }

        if($certsInfo[$i][1] < $GLOBALS["CERTIFICATE_VALIDITY"]) {
            $certsResults[$i][1] = "Certificate must be valid at least for " . $GLOBALS["CERTIFICATE_VALIDITY"] . " days. Yours is " . $certsInfo[$i][1] . ".";
        }
    }

    for($i=0; $i<count($certsResults); $i++) {
        if($i%2 === 0) {
            continue;
        }

        if(($certsResults[$i][0] !== null) || ($certsResults[$i][1] !== null)) {
            foreach($certsResults[$i] as $m) {
                array_push($messages, $m);
            }
        }

        if($certsResults[$i][0] !== null) {
            foreach($certsResults[$i] as $m) {
                array_push($messages, $m);
            }
        }
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: /md:EntityDescriptor/{md:IDPSSODescriptor,md:AttributeAuthorityDescriptor}/md:Extensions/shibmd:Scope
 */
function scopeCheck($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $xpath->registerNameSpace("shibmd", "urn:mace:shibboleth:metadata:1.0");
    $resultIDP = $xpath->query("/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/shibmd:Scope");
    $resultAA  = $xpath->query("/md:EntityDescriptor/md:AttributeAuthorityDescriptor/md:Extensions/shibmd:Scope");

    $messages = array();
    if($resultIDP->length !== 1) {
        array_push($messages, "Precisely 1 IDPSSODescriptor/Scope required.");
    }
    if($resultAA->length > 1) {
        array_push($messages, "Either 0 or 1 AttributeAuthorityDescriptor/Scope allowed.");
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: //shibmd:Scope[@regexp=false]
 */
function scopeRegexpCheck($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("shibmd", "urn:mace:shibboleth:metadata:1.0");
    $scopes = $xpath->query("//shibmd:Scope[@regexp]");

    $regexpValue = array();
    if($scopes->length > 0) {
        foreach($scopes as $s) {
            array_push($regexpValue, $s->getAttribute("regexp"));
        }
    }

    $messages = array();
    foreach($regexpValue as $regexp) {
        if(strcmp($regexp, "false") !== 0) {
            array_push($messages, "Scope regexp must be \"false\".");
        }
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: //shibmd:Scope === //EntityDescriptor[@entityID] substring
 */
function scopeValueCheck($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $xpath->registerNamespace("shibmd", "urn:mace:shibboleth:metadata:1.0");
    $entityDescriptor = $xpath->query("/md:EntityDescriptor");
    $scopes = $xpath->query("//shibmd:Scope[@regexp]");

    $entityID = $entityDescriptor->item(0)->getAttribute("entityID");
    $pattern = '/https:\/\/([a-z0-9_\-\.]+)\/.*/i';
    $replacement = '$1';
    $hostname = preg_replace($pattern, $replacement, $entityID);

    $scopeValue = array();
    if($scopes->length > 0) {
        foreach($scopes as $s) {
            array_push($scopeValue, $s->nodeValue);
        }
    }

    $messages = array();
    foreach($scopeValue as $scope) {
        if(preg_match("/$scope/", $hostname) !== 1) {
            array_push($messages, "Scope value must be a substring of the entityID!");
        }
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: //mdui:UIInfo
 */
function uiinfoCheck($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $xpath->registerNameSpace("mdui", "urn:oasis:names:tc:SAML:metadata:ui");

    $UIInfoDisplayNameCS        = $xpath->query('//mdui:UIInfo/mdui:DisplayName[@xml:lang="cs"]');
    $UIInfoDisplayNameEN        = $xpath->query('//mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]');
    $UIInfoDescriptionCS        = $xpath->query('//mdui:UIInfo/mdui:Description[@xml:lang="cs"]');
    $UIInfoDescriptionEN        = $xpath->query('//mdui:UIInfo/mdui:Description[@xml:lang="en"]');
    $UIInfoInformationURLCS     = $xpath->query('//mdui:UIInfo/mdui:InformationURL[@xml:lang="cs"]');
    $UIInfoInformationURLEN     = $xpath->query('//mdui:UIInfo/mdui:InformationURL[@xml:lang="en"]');
    $UIInfoLogo                 = $xpath->query('//mdui:UIInfo/mdui:Logo');

    $messages = array();
    if($UIInfoDisplayNameCS->length !== 1)
       array_push($messages, "UIInfo->DisplayName/cs missing.");
    if($UIInfoDisplayNameEN->length !== 1)
       array_push($messages, "UIInfo->DisplayName/en missing.");
    if($UIInfoDescriptionCS->length !== 1)
       array_push($messages, "UIInfo->Description/cs missing.");
    if($UIInfoDescriptionEN->length !== 1)
       array_push($messages, "UIInfo->Description/en missing.");
    if($UIInfoInformationURLCS->length !== 1)
       array_push($messages, "UIInfo->InformationURL/cs missing.");
    if($UIInfoInformationURLEN->length !== 1)
       array_push($messages, "UIInfo->InformationURL/en missing.");
    if(isIDP($metadata)) {
       if($UIInfoLogo->length < 1)
           array_push($messages, "UIInfo->Logo missing.");
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: //md:Organization
 */
function organizationCheck($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $organization = $xpath->query("/md:EntityDescriptor/md:Organization");

    $messages = array();
    if($organization->length == 0) {
        array_push($messages, "Organization missing.");
    } else {
        $OrganizationNameCS        = $xpath->query('/md:EntityDescriptor/md:Organization/md:OrganizationName[@xml:lang="cs"]');
        $OrganizationNameEN        = $xpath->query('/md:EntityDescriptor/md:Organization/md:OrganizationName[@xml:lang="en"]');
        $OrganizationDisplayNameCS = $xpath->query('/md:EntityDescriptor/md:Organization/md:OrganizationDisplayName[@xml:lang="cs"]');
        $OrganizationDisplayNameEN = $xpath->query('/md:EntityDescriptor/md:Organization/md:OrganizationDisplayName[@xml:lang="en"]');
        $OrganizationURLCS         = $xpath->query('/md:EntityDescriptor/md:Organization/md:OrganizationURL[@xml:lang="cs"]');
        $OrganizationURLEN         = $xpath->query('/md:EntityDescriptor/md:Organization/md:OrganizationURL[@xml:lang="en"]');

        if($OrganizationNameCS->length === 0)
            array_push($messages, "Organization->OrganizationName/cs missing.");
        if($OrganizationNameEN->length === 0)
            array_push($messages, "Organization->OrganizationName/en missing.");
        if($OrganizationDisplayNameCS->length === 0)
            array_push($messages, "Organization->OrganizationDisplayName/cs missing.");
        if($OrganizationDisplayNameEN->length === 0)
            array_push($messages, "Organization->OrganizationDisplayName/en missing.");
        if($OrganizationURLCS->length === 0)
            array_push($messages, "Organization->OrganizationURL/cs missing.");
        if($OrganizationURLEN->length === 0)
            array_push($messages, "Organization->OrganizationURL/en missing.");
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: //md:ContactPerson[@contactType=technical]
 */
function contactPersonTechnicalCheck($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $contactPersons = $xpath->query("/md:EntityDescriptor/md:ContactPerson[@contactType='technical']");

    $messages = array();
    if($contactPersons->length < 1) {
        array_push($messages, "ContactPerson/technical undefined.");
    } else {
        foreach($contactPersons as $c) {
            $givenName = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","GivenName");
            $sn        = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","SurName");
            $mail      = $c->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","EmailAddress");

            if(empty($givenName->item(0)->nodeValue)) {
                array_push($messages, "ContactPerson/technical->GivenName missing.");
            }
            if(empty($sn->item(0)->nodeValue)) {
                array_push($messages, "ContactPerson/technical->SurName missing.");
            }
            if(empty($mail->item(0)->nodeValue)) {
                array_push($messages, "ContactPerson/technical->EmailAddress missing.");
            } elseif(!preg_match("/^mailto\:/", $mail->item(0)->nodeValue)) {
                array_push($messages, "ContactPerson/technical->EmailAddress doesn't contain \"mailto:\" schema.");
            }
        }
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: checkRepublishRequest
 */
function checkRepublishRequest($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $xpath->registerNameSpace("eduidmd", "http://eduid.cz/schema/metadata/1.0");
    $republishRequestIDP = $xpath->query("/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/eduidmd:RepublishRequest");
    $republishRequestSP  = $xpath->query("/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/eduidmd:RepublishRequest");
    $republishRequest    = $xpath->query("/md:EntityDescriptor/md:Extensions/eduidmd:RepublishRequest");
    $republishTarget     = $xpath->query("/md:EntityDescriptor/md:Extensions/eduidmd:RepublishRequest/eduidmd:RepublishTarget");

    $messages = array();

    if(($republishRequestSP->length > 0) or ($republishRequestIDP->length > 0)) {
        array_push($messages, "RepublishRequest placed incorrectly.");
    } elseif($republishRequest->length > 0) {
        if($republishTarget->length > 0) {
            if(strcmp($GLOBALS['REPUBLISH_TARGET'], $republishTarget->item(0)->nodeValue) !== 0) {
                array_push($messages, "RepublishRequest->RepublishTarget misconfigured.");
            }
        } else {
            array_push($messages, "RepublishRequest->RepublishTarget missing.");
        }
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: check for HTTPS in URL addresses
 */
function checkHTTPS($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
    $xpath->registerNameSpace("mdui", "urn:oasis:names:tc:SAML:metadata:ui");
    $xpath->registerNameSpace("init", "urn:oasis:names:tc:SAML:profiles:SSO:request-init");
    $xpath->registerNameSpace("idpdisc", "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol");

    $URL = array();

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

    $messages = array();
    foreach($URL as $key => $value) {
        if(preg_match("/http\:\/\//", $value)) {
            array_push($messages, "HTTP found in $key.");
        }
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* validation function: AttributeAuthorityDescriptor[@protocolSupportEnumeration]
 */
function checkAAD($metadata) {
    $doc = new DOMDocument();
    $doc->load($metadata);
    $xpath = new DOMXpath($doc);
    $xpath->registerNameSpace("md", "urn:oasis:names:tc:SAML:2.0:metadata");

    $SAML2binding  = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    $SAML2protocol = "urn:oasis:names:tc:SAML:2.0:protocol";

    $messages = array();

    $AttributeAuthorityDescriptor = $xpath->query("/md:EntityDescriptor/md:AttributeAuthorityDescriptor");

    if($AttributeAuthorityDescriptor->length > 0) {
        $AttributeService = $xpath->query("/md:EntityDescriptor/md:AttributeAuthorityDescriptor/md:AttributeService");
        $protocols = $AttributeAuthorityDescriptor->item(0)->getAttribute("protocolSupportEnumeration");

        for($i=0; $i<$AttributeService->length; $i++) {
            if(strcmp($AttributeService->item($i)->getAttribute("Binding"), $SAML2binding) === 0) {
                if(!preg_match("/$SAML2protocol/", $protocols)) {
                    array_push($messages, "SAML 2.0 binding requires SAML 2.0 token in AttributeAuthorityDescriptor[@protocolSupportEnumeration].");
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
                    array_push($messages, "SAML 2.0 token in AttributeAuthorityDescriptor[@protocolSupportEnumeration] requires SAML 2.0 binding.");
            }
        }
    }

    list($returncode, $message) = generateResult($messages);
    return array($returncode, $message);
}

/* filename: metadata URL
 */
$filename = !empty ($_GET["filename"]) ? $_GET["filename"] : 0;

if (!$filename) {
    writeXML(2, "No metadata URL defined using HTTP GET variable `filename'.");
    exit;
}
else {
    if (!filter_var($filename, FILTER_VALIDATE_URL)) {
        writeXML(2, "Invalid metadata URL supplied in HTTP GET variable `filename'.");
        exit;
    }
}

/* fetch metadata
 */
if(!file_exists($TMP_DIRECTORY) || !is_dir($TMP_DIRECTORY)) {
    writeXML(2, "Create a `saml-validator/$TMP_DIRECTORY` directory writtable by a web-server user.");
    exit;
}
$URLsplit = explode ("/", $filename);
$encoded_entityid = $URLsplit[count($URLsplit)-2];
$metadata = $TMP_DIRECTORY . $encoded_entityid . uniqid('-') . ".xml";

!$md_content = @file_get_contents ("$filename");

if (empty ($md_content)) {
    writeXML(2, "Metadata file has no content.");
    exit;
} elseif (!$md_content) {
    writeXML(2, "No metadata URL");
    exit;
} else {
    file_put_contents ("$metadata", $md_content);
}

/* an array for storing validation results
 */
$validations = array ();

/* validate metadata and save results
 */
$validations["validMetadata"] = validateSAML($metadata);
if($validations["validMetadata"][0] === 0) {
    if(isIDP($metadata)) {
        $validations["scopeCheck"] = scopeCheck($metadata);
        $validations["scopeRegexpCheck"] = scopeRegexpCheck($metadata);
        $validations["scopeValueCheck"] = scopeValueCheck($metadata);
        $validations["checkAAD"] = checkAAD($metadata);
    }
    $validations["certificateCheck"] = certificateCheck($metadata);
    $validations["uiinfoCheck"] = uiinfoCheck($metadata);
    $validations["organizationCheck"] = organizationCheck($metadata);
    $validations["contactPersonTechnicalCheck"] = contactPersonTechnicalCheck($metadata);
    $validations["checkRepublishRequest"] = checkRepublishRequest($metadata);
    $validations["checkHTTPS"] = checkHTTPS($metadata);
}

/* delete downloaded metadata from $TMP_DIRECTORY
 */
if(!empty($_GET["d"])) {
    $delete     = $_GET["d"];
    $filename   = $_GET["filename"];

    if(filter_var($filename, FILTER_VALIDATE_URL, FILTER_FLAG_PATH_REQUIRED)) {
        if(strcmp($delete, "1") === 0) {
            $DIR = rtrim($TMP_DIRECTORY, "/");
            $file = preg_split("/$DIR\//", $filename);
            $file = $TMP_DIRECTORY . $file[1];
            exec("rm -f $file");
        } else {
            echo "Command not understood.";
        }
    } else {
        echo "No proper URL address specified.";
    }
}

/* get result and produce XML
 */
list($returncode, $message) = filterResult($validations);
writeXML($returncode, $message);

/* delete temporary XML file with metadata
 */
exec ("rm -f $metadata");

?>

