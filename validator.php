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

/*
 * Variable definitions
 *
 */
$KEY_SIZE = 2048;
$CERTIFICATE_VALIDITY = 300;
$XSD_VALIDATOR = "./xsd-validator/xsdv.sh";

/*
 * writeXML function to produce XML output
 *
 */
function writeXML($returncode, $info, $message) {
    $w = new XMLWriter();
    $w->openURI('php://output');
    $w->startDocument('1.0', 'utf-8');
    $w->setIndent(true);

    $w->startElement('validation');
        $w->writeElement('returncode', $returncode);
        $w->writeElement('info', $info);
        $w->writeElement('message', $message);
    $w->endElement();

    $w->endDocument();
    $w->flush();
}

/*
 * certificate check function
 *
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


/*
 * error messages definitions
 *
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
    "no_validator" => array(
        "code"  => 2,
        "info"  => "No validator selected in HTTP GET variable `validator'.",
    ),
    "nonexistent_validator" => array(
        "code"  => 2,
        "info"  => "Non-existent validator selected in HTTP GET variable `validator'.",
    ),
);

/*
 * output texts definitions
 *
 */
$info = array(
    "tech-c" => array(
        0 => "Technical contact is present.",
        2 => "Technical contact is missing! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
    ),

    "uiinfo" => array(
        0 => "UIInfo defined.",
        2 => "UIInfo undefined! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
    ),

    "endpoints-entityID" => array(
        0 => "Endpoints and entityID are all HTTPS.",
        2 => "Endpoints and entityID are required to be HTTPS! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
    ),

    "organization" => array(
        0 => "Organization defined.",
        2 => "Organization definition missing! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
    ),

    "republish-target" => array(
        0 => "Republish Target defined correctly or missing (which is OK).",
        2 => "Republish Target misconfigured! For more info, see https://www.eduid.cz/cs/tech/metadata-profile"
    ),

    "certificate" => array(
        0 => "Certificate present.",
        2 => "Certificate missing! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
    ),

    "certificate-check" => array(
        0 => "Certificate key size and validity correct.",
        2 => "Certificate key size or validity incorrect! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
    ),
);

/*
 * metadata URL check
 *
 */
$filename  = $_GET["filename"];

if(!$filename) {
    writeXML($error['no_URL']['code'], $error['no_URL']['info']);
    exit;

} else {
    if(!filter_var($filename, FILTER_VALIDATE_URL)) {
        writeXML($error['invalid_URL']['code'], $error['invalid_URL']['info']);
        exit;
    }
}

/*
 * validator check
 *
 */
$validator = $_GET["validator"];

if(!$validator) {
    writeXML($error['no_validator']['code'], $error['no_validator']['info']);
    exit;

} else {
    $validator = filter_var($validator, FILTER_SANITIZE_STRING);
}

/*
 * fetch metadata
 *
 */
$URLsplit = explode("/", $filename);
$encoded_entityid = $URLsplit[count($URLsplit)-2];
$metadata = "tmp/" . $encoded_entityid . ".xml";

file_put_contents("$metadata", file_get_contents("$filename"));

/*
 * select validator (XSD, etc.)
 *
 */
switch($validator) {
    case "tech-c":
        $xmlschema = "tech-c.xsd";
        break;

    case "uiinfo":
        $xmlschema = "uiinfo.xsd";
        break;

    case "endpoints-entityID":
        $xmlschema = "endpoints-entityID.xsd";
        break;

    case "organization":
        $xmlschema = "organization.xsd";
        break;

    case "republish-target":
        $xmlschema = "republish-target.xsd";
        break;

    case "certificate":
        $xmlschema = "certificate.xsd";
        break;

    case "certificate-check":
        list($returncode, $message) = certificateCheck($metadata);
        break;

    default:
        writeXML($error['nonexistent_validator']['code'], $error['nonexistent_validator']['info']);
        exit;
}

/*
 * validate metadata using XML Schema
 *
 */

if($xmlschema) {
    $command = "$XSD_VALIDATOR xsd/$xmlschema $metadata";
    exec($command, $output);

    foreach($output as $line)
        $message .= $line;

    if(preg_match("/validates/", $message)) {
        $returncode = 0;
        $message = "";

    } else {
        $returncode = 2;
    }
}

/*
 * validation result
 *
 */
writeXML($returncode, $info[$validator][$returncode], $message);

/*
 * delete temporary XML file with metadata
 *
 */
exec("rm -f $metadata");

?>

