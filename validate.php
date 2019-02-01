<?php

/**
 * Variables.
 */
$ALLOWED_MIMES = array("text/xml");

/**
 * getRequestMethod() returns the value of $_SERVER["REQUEST_METHOD"].
 */
function getRequestMethod() {
    return $_SERVER["REQUEST_METHOD"];
}

/**
 * isGet() returns true if $_SERVER["REQUEST_METHOD"] equals to GET.
 */
function isGet() {
    return strcmp(strtolower(getRequestMethod()), "get") === 0;
}

/**
 * isPost() returns true if $_SERVER["REQUEST_METHOD"] equals to POST.
 */
function isPost() {
    return strcmp(strtolower(getRequestMethod()), "post") === 0;
}

/**
 * validateURL() returns a valid HTTPS URL or throws an exception.
 */
function validateURL($url) {
    if(!filter_var($url, FILTER_VALIDATE_URL))
        throw new Exception("Invalid metadata URL defined in HTTP GET variable `link`.");

    elseif(!preg_match("/^https\:\/\//", $url))
        throw new Exception("Metadata URL defined in HTTP GET variable `link` must be HTTPS.");

    return $url;
}

/**
 * linkOrFile() returns a valid metadata link, the uploaded file or throws an
 * exception.
 */
function linkOrFile($link, $file) {
    if((empty($link) && $file["size"] === 0))
        throw new Exception("Neither metadata URL defined nor metadata file selected.");

    elseif(!empty($link) && $file["size"] > 0)
        throw new Exception("Either define metadata URL or select metadata file, not both.");

    elseif(!empty($link)) {
        validateURL($link);
        return $link;
    }

    elseif($file["size"] > 0)
        return $file;
}

/**
 * All the magic validate.php does is executed here.
 */
try {
    echo "<pre>";

    if(isGet()) {
        $link = !empty($_GET["link"]) ? $_GET["link"] : false;

        if(!$link)
            throw new Exception("No metadata URL defined in HTTP GET variable `link`.");

        validateURL($link);
    }

    if(isPost()) {
        $remoteMetadata = linkOrFile($_POST["link"], $_FILES["file"]);

        if(is_array($remoteMetadata))
            $metadata = $remoteMetadata["tmp_name"];
        else
            $metadata = $remoteMetadata;
    }

    include "./validator.php";

} catch(Throwable $t) {
    echo "Caught Exception: ", $t->getMessage(), "\n";

} catch(Exception $e) {
    echo "Caught Exception: ", $e->getMessage(), "\n";
}

