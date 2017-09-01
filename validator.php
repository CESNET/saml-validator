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

/* writeXML function to produce XML output
 *
 * FIXME: rewrite to just a dumb function writeXML (return code, info message, debug message)
 *
 */
function writeXML ($returncode, $validations, $debug) {
    $xml = new XMLWriter();
    $xml->openURI('php://output');
    $xml->startDocument('1.0', 'utf-8');
    $xml->setIndent(true);

    $xml->startElement('validation');

        $xml->writeElement('returncode', $returncode);

        foreach ($validations as $validation) {
            if (!empty ($validation["message"]))
                $xml->writeElement ('message', $validation["message"]);
        }

    $xml->endElement();

    $xml->endDocument();
    $xml->flush();
}

/* writeXMLError function to produce various error messages as a XML document
 *
 * FIXME: see writeXML() FIXME
 */
function writeXMLError ($returncode, $message) {
    $xml = new XMLWriter ();
    $xml->openURI ("php://output");
    $xml->startDocument ("1.0", "utf-8");
    $xml->setIndent ("true");
    $xml->startElement ("validation");
    $xml->writeElement ("returncode", $returncode);
    $xml->writeElement ("message", $message);
    $xml->endElement ();
    $xml->endDocument ();
    $xml->flush ();
}

/* isIDP function returns true in case $metadata is IdP
 */
function isIDP ($metadata) {
    $sxe = new SimpleXMLElement (file_get_contents ($metadata));
    $sxe->registerXPathNamespace ('md','urn:oasis:names:tc:SAML:2.0:metadata');
    $result = $sxe->xpath ('//md:IDPSSODescriptor');

    if (count ($result) > 0) {
        return true;
    }
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
function certificateCheck ($metadata) {
    $sxe = new SimpleXMLElement (file_get_contents($metadata));
    $sxe->registerXPathNamespace ('ds','http://www.w3.org/2000/09/xmldsig#');
    $result = $sxe->xpath ('//ds:X509Certificate');

    if (count ($result) > 0) {

        foreach ($result as $cert) {
            $X509Certificate = "-----BEGIN CERTIFICATE-----\n" . trim ($cert) . "\n-----END CERTIFICATE-----";
            $cert_info = openssl_x509_parse ($X509Certificate, true);
            $cert_validTo = date ("Y-m-d", $cert_info['validTo_time_t']);
            $cert_validFor = floor ((strtotime ($cert_validTo)-time ())/(60*60*24));
            $pub_key = openssl_pkey_get_details (openssl_pkey_get_public ($X509Certificate));

            if (($pub_key['bits'] >= $GLOBALS['KEY_SIZE']) && ($cert_validFor >= $GLOBALS['CERTIFICATE_VALIDITY'])) {
                $returncode = 0;
                #$message = "Public key size is at least " . $GLOBALS['KEY_SIZE'] . ". That is OK.";
                $message = "";
            } elseif (($pub_key['bits'] < $GLOBALS['KEY_SIZE']) && ($cert_validFor >= $GLOBALS['CERTIFICATE_VALIDITY'])) {
                $returncode = 2;
                $message = "Public key size has to be greater than or equal to " . $GLOBALS['KEY_SIZE'] . ". Yours is " . $pub_key[bits] . ".";
            } elseif (($pub_key['bits'] >= $GLOBALS['KEY_SIZE']) && ($cert_validFor < $GLOBALS['CERTIFICATE_VALIDITY'])) {
                $returncode = 2;
                $message = "Certificate should be valid at least for " . $GLOBALS['CERTIFICATE_VALIDITY'] . " days. Yours is valid only for " . $cert_validFor . ".";
            } else {
                $returncode = 2;
                $message = "Certificate should be valid at least for " . $GLOBALS['CERTIFICATE_VALIDITY'] . " days. Yours is valid only for " . $cert_validFor . ". And public key size has to be greater than or equal to " . $GLOBALS['KEY_SIZE'] . " bits. Yours is " . $pub_key[bits] . ".";
            }
        }

        return array($returncode, $message);

    } else {
        $returncode = 2;
        $message    = "No certificate found.";
        return array ($returncode, $message);
    }
}

/* validation function: /md:EntityDescriptor/{md:IDPSSODescriptor,md:AttributeAuthorityDescriptor}/md:Extensions/shibmd:Scope
 */
function scopeCheck($metadata) {
    $sxe = new SimpleXMLElement(file_get_contents($metadata));
    $sxe->registerXPathNamespace('md','urn:oasis:names:tc:SAML:2.0:metadata');
    $sxe->registerXPathNamespace('shibmd','urn:mace:shibboleth:metadata:1.0');
    $resultIDP = $sxe->xpath('/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/shibmd:Scope');
    $resultAA  = $sxe->xpath('/md:EntityDescriptor/md:AttributeAuthorityDescriptor/md:Extensions/shibmd:Scope');

    $messages = array();
    if(count($resultIDP) !== 1) {
        array_push($messages, "Precisely 1 IDPSSODescriptor/Scope required.");
    }
    if(count($resultAA) > 1) {
        array_push($messages, "Either 0 or 1 AttributeAuthorityDescriptor/Scope allowed.");
    }

    $message = "";
    if(count($messages) > 0) {
        $returncode = 2;
        for($i=0; $i<=count($messages); $i++) {
            $message .= array_pop($messages) . " ";
        }
    } else {
        $returncode = 0;
    }

    return array($returncode, $message);
}

/* validation function: //shibmd:Scope[@regexp=false]
 */
function scopeRegexpCheck ($metadata) {
    $sxe = new SimpleXMLElement (file_get_contents($metadata));
    $sxe->registerXPathNamespace ('shibmd','urn:mace:shibboleth:metadata:1.0');
    $result = $sxe->xpath ('//shibmd:Scope[@regexp]');
    $resultCount = count ($result);

    $regexpValue = array ();
    for ($i=0; $i<$resultCount; $i++) {
        $regexpValue[$i] = (string) $result[$i]['regexp'];
    }

    $regexpResult = -1;
    foreach ($regexpValue as $regexp) {
        if (strcmp ($regexp, 'false') === 0) {
            $returncode = 0;
        } else {
            $returncode = 2;
        }

        $regexpResult = max ($regexpResult, $returncode);
    }

    $regexpMessage = array (
        -1 => 'Something went wrong with scope regexp check.',
         #0 => 'Scope regexp is false. That is OK.',
         0 => '',
         2 => 'Scope regexp must be "false"!',
    );

    return array ($regexpResult, $regexpMessage[$regexpResult]);
}

/* validation function: //shibmd:Scope === //EntityDescriptor[@entityID] substring
 */
function scopeValueCheck ($metadata) {
    $sxe = new SimpleXMLElement (file_get_contents($metadata));
    $sxe->registerXPathNamespace ('md','urn:oasis:names:tc:SAML:2.0:metadata');
    $entityID = $sxe->xpath ('/md:EntityDescriptor[@entityID]');
    $entityID = ((string) $entityID[0]['entityID']);
    $pattern = '/https:\/\/([a-z0-9_\-\.]*)\/.*/i';
    $replacement = '$1';
    $hostname = preg_replace ($pattern, $replacement, $entityID);

    $sxe->registerXPathNamespace ('shibmd','urn:mace:shibboleth:metadata:1.0');
    $result = $sxe->xpath ('//shibmd:Scope[@regexp]');
    $resultCount = count ($result);

    $scopeValue = array ();
    for ($i=0; $i<$resultCount; $i++) {
        $scopeValue[$i] = (string) $result[$i][0];
    }

    $scopeResult = -1;
    foreach ($scopeValue as $scope) {
        if (preg_match ("/$scope/", $hostname)) {
            $regResult = 0;
        } else {
            $regResult = 2;
        }
        $scopeResult = max ($scopeResult, $regResult);
    }

    $scopeMessage = array (
        -1 => 'Something went wrong with scope value check.',
         #0 => 'Scope value is a substring of the entityID. That is OK.',
         0 => '',
         2 => 'Scope value must be a substring of the entityID!',
    );

    return array ($scopeResult, $scopeMessage[$scopeResult]);
}

/* validation function: //mdui:UIInfo
 */
function uiinfoCheck ($metadata) {
    $sxe = new SimpleXMLElement (file_get_contents($metadata));
    $sxe->registerXPathNamespace ('md','urn:oasis:names:tc:SAML:2.0:metadata');
    $sxe->registerXPathNamespace ('mdui','urn:oasis:names:tc:SAML:metadata:ui');

    $UIInfoDisplayNameCS        = $sxe->xpath ('//mdui:UIInfo/mdui:DisplayName[@xml:lang="cs"]');
    $UIInfoDisplayNameEN        = $sxe->xpath ('//mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]');
    $UIInfoDescriptionCS        = $sxe->xpath ('//mdui:UIInfo/mdui:Description[@xml:lang="cs"]');
    $UIInfoDescriptionEN        = $sxe->xpath ('//mdui:UIInfo/mdui:Description[@xml:lang="en"]');
    $UIInfoInformationURLCS     = $sxe->xpath ('//mdui:UIInfo/mdui:InformationURL[@xml:lang="cs"]');
    $UIInfoInformationURLEN     = $sxe->xpath ('//mdui:UIInfo/mdui:InformationURL[@xml:lang="en"]');
    $UIInfoLogo                 = $sxe->xpath ('//mdui:UIInfo/mdui:Logo');

    $messages = array();
    if (empty ($UIInfoDisplayNameCS))
        array_push ($messages, "DisplayName/cs missing.");
    if (empty ($UIInfoDisplayNameEN))
        array_push ($messages, "DisplayName/en missing.");
    if (empty ($UIInfoDescriptionCS))
        array_push ($messages, "Description/cs missing.");
    if (empty ($UIInfoDescriptionEN))
        array_push ($messages, "Description/en missing.");
    if (empty ($UIInfoInformationURLCS))
        array_push ($messages, "InformationURL/cs missing.");
    if (empty ($UIInfoInformationURLEN))
        array_push ($messages, "InformationURL/en missing.");
    if (isIDP ($metadata)) {
        if (empty ($UIInfoLogo))
            array_push ($messages, "Logo missing.");
    }

    $message = "";
    if (count ($messages) > 0) {
        $returncode = 2;
        for ($i=0; $i<=count ($messages); $i++) {
            $message .= array_pop ($messages) . " ";
        }
    } else {
        $returncode = 0;
    }

    return array ($returncode, $message);
}

/* validation function: //md:Organization
 */
function organizationCheck ($metadata) {
    $sxe = new SimpleXMLElement (file_get_contents($metadata));
    $sxe->registerXPathNamespace ('md','urn:oasis:names:tc:SAML:2.0:metadata');
    $result = $sxe->xpath ('/md:EntityDescriptor/md:Organization');

    if (count ($result) > 0) {
        $returncode = 0;
        $message    = "";
    } else {
        $returncode = 2;
        $message    = "Organization undefined.";
    }

    return array ($returncode, $message);
}

/* validation function: //md:ContactPerson[@contactType=technical]
 */
function contactPersonTechnicalCheck($metadata) {
    $sxe = new SimpleXMLElement(file_get_contents($metadata));
    $sxe->registerXPathNamespace('md','urn:oasis:names:tc:SAML:2.0:metadata');
    $contactPerson = $sxe->xpath('/md:EntityDescriptor/md:ContactPerson[@contactType="technical"]');

    $messages = array();
    if(count($contactPerson) < 1) {
        array_push($messages, "ContactPerson undefined.");
    } else {
        foreach($contactPerson as $c) {
            if(empty($c->GivenName)) {
                array_push($messages, "GivenName missing in " . $c->getName() . ".");
            }
            if(empty($c->SurName)) {
                array_push($messages, "SurName missing in " . $c->getName() . ".");
            }
            if(empty($c->EmailAddress)) {
                array_push($messages, "EmailAddress missing in " . $c->getName() . ".");
            }
        }
    }

    $returncode = null;
    $message    = null;
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

/* validation function: checkRepublishRequest
 */
function checkRepublishRequest($metadata) {
    $sxe = new SimpleXMLElement(file_get_contents($metadata));
    $sxe->registerXPathNamespace('md','urn:oasis:names:tc:SAML:2.0:metadata');
    $sxe->registerXPathNamespace('eduidmd','http://eduid.cz/schema/metadata/1.0');
    $republishRequest = $sxe->xpath('/md:EntityDescriptor/md:Extensions/eduidmd:RepublishRequest');
    $republishTarget  = $sxe->xpath('/md:EntityDescriptor/md:Extensions/eduidmd:RepublishRequest/eduidmd:RepublishTarget');

    if(count($republishRequest) > 0) {
        if(count($republishTarget) > 0) {
            if(strcmp($GLOBALS['REPUBLISH_TARGET'], (string) $republishTarget[0][0]) === 0) {
                $returncode = 0;
                #$message    = "RepublishRequest OK.";
                $message    = "";
            } else {
                $returncode = 2;
                $message    = "RepublishTarget misconfigured.";
            }
        } else {
            $returncode = 2;
            $message    = "RepublishTarget missing.";
        }
    } else {
        $returncode = 0;
        #$message    = "No RepublishRequest found. That's OK.";
        $message    = "";
    }

    return array($returncode, $message);
}

/* validation function: check for HTTPS in URL addresses
 */
function checkHTTPS($metadata) {
    $sxe = new SimpleXMLElement(file_get_contents($metadata));
    $sxe->registerXPathNamespace('md','urn:oasis:names:tc:SAML:2.0:metadata');
    $sxe->registerXPathNamespace('mdui','urn:oasis:names:tc:SAML:metadata:ui');
    $sxe->registerXPathNamespace('init','urn:oasis:names:tc:SAML:profiles:SSO:request-init');
    $sxe->registerXPathNamespace('idpdisc','urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol');

    $URL = array();

    # /md:EntityDescriptor[@entityID]
    $entityID = $sxe->xpath('/md:EntityDescriptor[@entityID]');
    $entityID = ((string) $entityID[0]['entityID']);
    $URL['entityID'] = $entityID;

    # //mdui:UIInfo/mdui:Logo
    $Logo = $sxe->xpath('//mdui:UIInfo/mdui:Logo');
    for($i=0; $i<count($Logo); $i++) {
        $URL['Logo'.$i] = (string) $Logo[$i][0];
    }

    # //md:ArtifactResolutionService
    $ArtifactResolutionService = $sxe->xpath('/md:EntityDescriptor//md:ArtifactResolutionService');
    for($i=0; $i<count($ArtifactResolutionService); $i++) {
        $URL['ArtifactResolutionService'.$i] = (string) $ArtifactResolutionService[$i]['Location'];
    }

    # //md:SingleLogoutService
    $SingleLogoutService = $sxe->xpath('/md:EntityDescriptor//md:SingleLogoutService');
    for($i=0; $i<count($SingleLogoutService); $i++) {
        $URL['SingleLogoutService'.$i] = (string) $SingleLogoutService[$i]['Location'];
    }

    # //md:SingleSignOnService
    $SingleSignOnService = $sxe->xpath('/md:EntityDescriptor//md:SingleSignOnService');
    for($i=0; $i<count($SingleSignOnService); $i++) {
        $URL['SingleSignOnService'.$i] = (string) $SingleSignOnService[$i]['Location'];
    }

    # //md:AttributeService
    $AttributeService = $sxe->xpath('/md:EntityDescriptor/md:AttributeAuthorityDescriptor/md:AttributeService');
    for($i=0; $i<count($AttributeService); $i++) {
        $URL['AttributeService'.$i] = (string) $AttributeService[$i]['Location'];
    }

    # //init:RequestInitiator
    $RequestInitiator = $sxe->xpath('/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/init:RequestInitiator');
    for($i=0; $i<count($RequestInitiator); $i++) {
        $URL['RequestInitiator'.$i] = (string) $RequestInitiator[$i]['Location'];
    }

    # //idpdisc:DiscoveryResponse
    $DiscoveryResponse = $sxe->xpath('/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/idpdisc:DiscoveryResponse');
    for($i=0; $i<count($DiscoveryResponse); $i++) {
        $URL['DiscoveryResponse'.$i] = (string) $DiscoveryResponse[$i]['Location'];
    }

    # //md:AssertionConsumerService
    $AssertionConsumerService = $sxe->xpath('/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService');
    for($i=0; $i<count($AssertionConsumerService); $i++) {
        $URL['AssertionConsumerService'.$i] = (string) $AssertionConsumerService[$i]['Location'];
    }

    $messages = array();
    foreach($URL as $key => $value) {
        if(preg_match("/http\:\/\//", $value)) {
            array_push($messages, "HTTP found in $key.");
        }
    }

    $message = "";
    if(count($messages) > 0) {
        $returncode = 2;
        for($i=0; $i<count($messages); $i++) {
            $message .= array_pop($messages) . " ";
        }
    } else {
        $returncode = 0;
    }

    return array($returncode, $message);
}

/* debug: show <info> elements even for success validations
 *  value 0 (default) means no debug
 *  value 1 means debug
 *  other values produces $debug=1
 *
 *  FIXME: clear input fileds
 */
$debug = !empty ($_GET["debug"]) ? 1 : 0;

/* filename: metadata URL
 */
$filename = !empty ($_GET["filename"]) ? $_GET["filename"] : 0;

if (!$filename) {
    writeXMLError (2, "No metadata URL defined using HTTP GET variable `filename'.");
    exit;
}
else {
    if (!filter_var($filename, FILTER_VALIDATE_URL)) {
        writeXMLError(2, "Invalid metadata URL supplied in HTTP GET variable `filename'.");
        exit;
    }
}

/* fetch metadata
 */
$URLsplit = explode ("/", $filename);
$encoded_entityid = $URLsplit[count($URLsplit)-2];
$metadata = "tmp/" . $encoded_entityid . uniqid('-') . ".xml";

!$md_content = @file_get_contents ("$filename");

if (empty ($md_content)) {
    writeXMLError (2, "Metadata file has no content.");
    exit;
} elseif (!$md_content) {
    writeXMLError (2, "No metadata URL");
    exit;
} else {
    file_put_contents ("$metadata", $md_content);
}

/* an array for storing validation results
 */
$validations = array ();

// validate metadata against XSD schema
list($returncode, $message) = validateSAML($metadata);
$result = array(
    "returncode" => $returncode,
    "message"    => $message,
);
$validations["validMetadata"] = $result;

if($returncode === 0) {
    /* run enabled validators (PHP scripts)
     */
    // certificate validity
    list ($returncode, $message) = certificateCheck ($metadata);
    $result = array (
        "returncode" => $returncode,
        "message"    => $message,
    );
    $validations ["certificateCheck"] = $result;

    // shibmd:Scope tests
    if (isIDP ($metadata)) {
        // shibmd:Scope
        list($returncode, $message) = scopeCheck($metadata);
        $result = array(
            "returncode" => $returncode,
            "message"    => $message,
        );
        $validations["scopeCheck"] = $result;

        // shibmd:Scope[@regexp=false]
        list ($returncode, $message) = scopeRegexpCheck ($metadata);
        $result = array (
            "returncode" => $returncode,
            "message"    => $message,
        );
        $validations ["scopeRegexpCheck"] = $result;

        // shibmd:Scope === substr(entityID)
        list ($returncode, $message) = scopeValueCheck ($metadata);
        $result = array (
            "returncode" => $returncode,
            "message"    => $message,
        );
        $validations ["scopeValueCheck"] = $result;
    }

    // uiinfo
    list ($returncode, $message) = uiinfoCheck ($metadata);
    $result = array (
        "returncode" => $returncode,
        "message"    => $message,
    );
    $validations ["uiinfoCheck"] = $result;

    // organization
    list ($returncode, $message) = organizationCheck ($metadata);
    $result = array (
        "returncode" => $returncode,
        "message"    => $message,
    );
    $validations ["organizationCheck"] = $result;

    // technical contact
    list ($returncode, $message) = contactPersonTechnicalCheck ($metadata);
    $result = array (
        "returncode" => $returncode,
        "message"    => $message,
    );
    $validations ["contactPersonTechnicalCheck"] = $result;

    // republish request
    list($returncode, $message) = checkRepublishRequest($metadata);
    $result = array(
        "returncode" => $returncode,
        "message"    => $message,
    );
    $validations["checkRepublishRequest"] = $result;

    // HTTPS URLs
    list($returncode, $message) = checkHTTPS($metadata);
    $result = array(
        "returncode" => $returncode,
        "message"    => $message,
    );
    $validations["checkHTTPS"] = $result;
}

/* validation result
 */
$returncode_final = -1;
foreach ($validations as $validation) {
    $returncode_final = max ($returncode_final, $validation["returncode"]);
}

writeXML ($returncode_final, $validations, $debug);

/* delete temporary XML file with metadata
 */
exec ("rm -f $metadata");

?>

