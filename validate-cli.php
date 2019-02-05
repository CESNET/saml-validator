<?php

/**
 * Import helpers, etc.
 */
require_once(dirname(__FILE__) . "/functions.php");
require_once(dirname(__FILE__) . "/validator.php");

/**
 * This file is not intended to be run from a web server, CLI only.
 */
if(@isGet())
    exit();

/**
 * Do we have an argument (a metadata file) or stdin (a metadata content)?
 */
$stdin = false;

if(@$argv[1]) {
    $metadata = @getVariable($argv[1]);

    /*
     *if(!$metadata) {
     *    echo "Missing an argument pointing to a metadata file.\n";
     *    exit(1);
     *}
     */

    if(!file_exists($metadata)) {
        echo $metadata . " does not exists.\n";
        exit(2);
    }

    if(!is_file($metadata)) {
        echo $metadata . " is not a file.\n";
        exit(3);
    }
} else {
    $metadata = getStdin();
    $stdin    = true;
}

/**
 * Validate the metadata and exit with error code '0' if everything's OK.
 */
validateMetadata($metadata, $cli = true, $stdin);

