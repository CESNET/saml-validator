<?php

/**
 * Require statements.
 */
require_once("./functions.php");

/**
 * All the magic validate.php does is executed here.
 */
try {
    echo "<pre>";

    $metadata = getMetadata();

    require_once("./validator.php");

} catch(Throwable $t) {
    echo "Caught Exception: ", $t->getMessage(), "\n";

} catch(Exception $e) {
    echo "Caught Exception: ", $e->getMessage(), "\n";
}

