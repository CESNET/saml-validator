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
    $result = validateMetadata(getMetadata());

    if(!empty($result["warning"]))
        echo "WARNING: ", $result["warning"], "<br>\n";

    if(!empty($result["error"]))
        echo "ERROR: ", $result["error"], "<br>\n";

    echo "RESULT: ", $result["result"];

} catch(Throwable $t) {
    echo "Caught Exception: ", $t->getMessage(), "\n";

} catch(Exception $e) {
    echo "Caught Exception: ", $e->getMessage(), "\n";
}

