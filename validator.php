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
 * SAML-Validator (XML schemas, PHP, etc.) is written by Jan Oppolzer [5] from
 * CESNET [6] and can be obtained from GitHub repository [7].
 *
 * [1] http://jagger.heanet.ie/
 * [2] https://github.com/amouat/xsd-validator/
 * [3] https://github.com/amouat/
 * [4] http://www.adrianmouat.com/
 * [5] jan.oppolzer@cesnet.cz
 * [6] https://www.cesnet.cz/
 * [7] https://github.com/JanOppolzer/saml-validator/
 *
 */

/*
 * Validator definition
 *
 */
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
        0 => "OK",
        2 => "Error",
    ),

    "endpoints-entityID" => array(
        0 => "Endpoints and entityID are all HTTPS.",
        2 => "Endpoints and entityID are required to be HTTPS! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
    ),

    "organization" => array(
        0 => "Organization defined.",
        2 => "Organization definition missing! For more info, see https://www.eduid.cz/cs/tech/metadata-profile",
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

        default:
            writeXML($error['nonexistent_validator']['code'], $error['nonexistent_validator']['info']);
            exit;
    }
}

/*
 * debug option
 *
 */
$DEBUG = $_GET['DEBUG'];

if($DEBUG) {
    $DEBUG = filter_var($DEBUG, FILTER_SANITIZE_NUMBER_INT);
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
 * validate metadata
 *
 */
$command = "$XSD_VALIDATOR xsd/$xmlschema $metadata";
exec($command, $output);

foreach($output as $line)
    $message .= $line;

if(preg_match("/validates/", $message)) {
    $returncode = 0;

} else {
    $returncode = 2;
}

if($_GET[DEBUG] != 1)
    $message = "";

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

