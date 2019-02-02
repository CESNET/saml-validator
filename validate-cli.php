<?php

/**
 * We need a metadata file to validate as the first CLI argument. Additional
 * arguments are ignored.
 */
$file = !empty($argv[1]) ? $argv[1] : false;

/**
 * If there's no CLI argument, exit with error code '1'.
 */
if(!$file) {
    echo "Missing an argument pointing to a metadata file.\n";
    exit(1);
}

/**
 * If the specified file does not exist, exit with error code '2'.
 */
if(!file_exists($file)) {
    echo $file . " does not exists.\n";
    exit(2);
}

/**
 * If the first argument isn't a file, exit with error code '3'.
 */
if(!is_file($file)) {
    echo $file . " is not a file.\n";
    exit(3);
}

/**
 * Validate the metadata and exit with error code '0' if everything's OK.
 */
include_once './validator.php';
validateMetadata($file, $cli = true);

