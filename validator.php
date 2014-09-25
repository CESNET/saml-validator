<?php

/*
 * Download and validate metadata from JAGGER [1].
 *
 * Metadata URL has to be passed via HTTP GET variable called `filename'
 * defined in Federation Validators settings (JAGGER). Then, metadata is saved
 * as a XML file `ENCODED_ENTITYID'.xml (ENCODED_ENTITYID is generated
 * automatically by JAGGER) in `tmp/' subdirectory which must exists and be
 * writable by the user running web server. After validation process is
 * finished, the temporary XML file with metadata is deleted.
 *
 * As a XML validator, XSD-Validator [2] by Adrian Mouat [3,4] is deployed.
 *
 * SAML-Validators (XML schemas, PHP, etc.) is written by Jan Oppolzer [5] from
 * CESNET [6] and can be obtained from GitHub repository [7].
 *
 * [1] http://jagger.heanet.ie/
 * [2] https://github.com/amouat/xsd-validator/
 * [3] https://github.com/amouat/
 * [4] http://www.adrianmouat.com/
 * [5] jan.oppolzer@cesnet.cz
 * [6] https://www.cesnet.cz/
 * [7] https://github.com/JanOppolzer/saml-validators/
 *
 */

/* variable definitions
 */
$KEY_SIZE               = 1024; # bits
$CERTIFICATE_VALIDITY   = 180;  # days
$XSD_VALIDATOR          = "./xsd-validator/xsdv.sh";

/* validators
 */
$VALIDATORS = array(
    "tech-c" => array(
        "enabled" => 1,
        "xmlschema" => "tech-c.xsd",
        "info" => array(
            0 => "Technical contact is present.",
            2 => "Technical contact is missing! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
        ),
    ),
    "uiinfo" => array(
        "enabled" => 1,
        "xmlschema" => "uiinfo.xsd",
        "info" => array(
            0 => "UIInfo defined.",
            2 => "UIInfo undefined! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
        ),
    ),
    "endpoints-entityID" => array(
        "enabled" => 1,
        "xmlschema" => "endpoints-entityID.xsd",
        "info" => array(
            0 => "Endpoints and entityID are all HTTPS.",
            2 => "Endpoints and entityID are required to be HTTPS! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
        ),
    ),
    "organization" => array(
        "enabled" => 1,
        "xmlschema" => "organization.xsd",
        "info" => array(
            0 => "Organization defined.",
            2 => "Organization definition missing! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
        ),
    ),
    "republish-target" => array(
        "enabled" => 1,
        "xmlschema" => "republish-target.xsd",
        "info" => array(
            0 => "Republish Target defined correctly or missing (which is OK).",
            2 => "Republish Target misconfigured! For more info, see https://www.eduid.cz/cs/tech/metadata-profile"
        ),
    ),
    "certificate" => array(
        "enabled" => 1,
        "xmlschema" => "certificate.xsd",
        "info" => array(
            0 => "Certificate present.",
            2 => "Certificate missing! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
        ),
    ),
);

/* writeXML function to produce XML output
 */
function writeXML($returncode, $validations, $debug = 0) {
    $w = new XMLWriter();
    $w->openURI('php://output');
    $w->startDocument('1.0', 'utf-8');
    $w->setIndent(true);

    $w->startElement('validation');
        $w->writeElement('returncode', $returncode);
        foreach($validations as $result => $validator) {
            if($debug === 1 && !empty($GLOBALS[VALIDATORS][$result][info][$validator[returncode]])) {
                $w->writeElement('info', $GLOBALS[VALIDATORS][$result][info][$validator[returncode]]);
            }
        }
        foreach($validations as $validation) {
            if(!empty($validation[message]))
                $w->writeElement('message', $validation[message]);
        }
    $w->endElement();

    $w->endDocument();
    $w->flush();
}

/* validate (using XML Schema) function
 */
function validateMetadata($metadata, $xmlschema) {
    $command = "$GLOBALS[XSD_VALIDATOR] xsd/$xmlschema $metadata";
    exec($command, $output);

    foreach($output as $line)
        $message .= $line;

    if(preg_match("/validates/", $message)) {
        $returncode = 0;
        $message = "";

    } else {
        $returncode = 2;
    }

    return array($returncode, $message);
}

/* certificate check function
 */
function certificateCheck($metadata) {
    $sxe = new SimpleXMLElement(file_get_contents($metadata));
    $sxe->registerXPathNamespace('ds','http://www.w3.org/2000/09/xmldsig#');
    $result = $sxe->xpath('//ds:X509Certificate');

    foreach($result as $cert) {
        $X509Certificate = "-----BEGIN CERTIFICATE-----\n" . trim($cert) . "\n-----END CERTIFICATE-----";
        $cert_info = openssl_x509_parse($X509Certificate, true);
        $cert_validTo = date("Y-m-d", $cert_info[validTo_time_t]);
        $cert_validFor = floor((strtotime($cert_validTo)-time())/(60*60*24));
        $pub_key = openssl_pkey_get_details(openssl_pkey_get_public($X509Certificate));
        $pub_key[bits] = 1024;

        if(($pub_key[bits] >= $GLOBALS['KEY_SIZE']) && ($cert_validFor >= $GLOBALS['CERTIFICATE_VALIDITY'])) {
            $returncode = 0;
        } elseif(($pub_key[bits] < $GLOBALS['KEY_SIZE']) && ($cert_validFor >= $GLOBALS['CERTIFICATE_VALIDITY'])) {
            $returncode = 2;
            $message = "Public key size has to be greater than or equal to " . $GLOBALS['KEY_SIZE'] . ". Yours is " . $pub_key[bits] . ".";
        } elseif(($pub_key[bits] >= $GLOBALS['KEY_SIZE']) && ($cert_validFor < $GLOBALS['CERTIFICATE_VALIDITY'])) {
            $returncode = 2;
            $message = "Certificate should be valid at least for " . $GLOBALS['CERTIFICATE_VALIDITY'] . " days. Yours is valid only for " . $cert_validFor . ".";
        } else {
            $returncode = 2;
            $message = "Certificate should be valid at least for " . $GLOBALS['CERTIFICATE_VALIDITY'] . " days. Yours is valid only for " . $cert_validFor . ". And public key size has to be greater than or equal to " . $GLOBALS['KEY_SIZE'] . " bits. Yours is " . $pub_key[bits] . ".";
        }
    }

    return array($returncode, $message);
}


/* error messages definitions
 */
$error = array(
    "no_URL" => array(
        "code"  => 2,
        "info"  => "No metadata URL supplied in HTTP GET variable `filename'.",
    ),
    "invalid_URL" => array(
        "code"  => 2,
        "info"  => "Invalid metadata URL supplied in HTTP GET variable `filename'.",
    ),
);

/* output texts definitions
 */
$info = array(
    "certificate-check" => array(
        0 => "Certificate key size and validity correct.",
        2 => "Certificate key size or validity incorrect! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
    ),
);

/* metadata URL check
 */
$filename = $_GET["filename"];

if(!$filename) {
    writeXML($error['no_URL']['code'], $error['no_URL']['info']);
    exit;

} else {
    if(!filter_var($filename, FILTER_VALIDATE_URL)) {
        writeXML($error['invalid_URL']['code'], $error['invalid_URL']['info']);
        exit;
    }
}

/* debug: show <info> elements even for success validations
 */
$debug = $_GET["debug"];

if(!empty($debug)) {
    $debug = 1;
}

/* fetch metadata
 */
$URLsplit = explode("/", $filename);
$encoded_entityid = $URLsplit[count($URLsplit)-2];
$metadata = "tmp/" . $encoded_entityid . ".xml";

file_put_contents("$metadata", file_get_contents("$filename"));

/* run enabled validators (against XML Schemas)
 */
$validations = array();
foreach($VALIDATORS as $validator => $value) {
    if($VALIDATORS[$validator][enabled] == 1) {
        list($returncode, $message) = validateMetadata($metadata, $VALIDATORS[$validator][xmlschema]);

        $result = array(
            "returncode" => $returncode,
            "message" => $message,
        );

        $validations[$validator] = $result;
    }
}

/* run enabled validators (for now only certificate check by PHP function)
 */
list($returncode, $message) = certificateCheck($metadata);
$validations["certificate-check"] = array(
    "returncode" => $returncode,
    "message" => $message,
);

/* validation result
 */
$returncode_max = -1;
foreach($validations as $validation) {
    $returncode = max($returncode_max, $validation['returncode']);
}
writeXML($returncode, $validations, $debug);

/* delete temporary XML file with metadata
 */
exec("rm -f $metadata");

?>

