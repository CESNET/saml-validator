<?php

/**
 * Require statements.
 */
require_once("./functions.php");
require_once("./validator.php");

/**
 * All the magic validate.php does is executed here.
 */
try {
    echo "<pre>";

    validateMetadata(getMetadata());

} catch(Throwable $t) {
    echo "Caught Exception: ", $t->getMessage(), "\n";

} catch(Exception $e) {
    echo "Caught Exception: ", $e->getMessage(), "\n";
}

