<?php

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
        throw new Exception("Invalid metadata URL.");

    elseif(!preg_match("/^https\:\/\//", $url))
        throw new Exception("Metadata URL must be HTTPS.");

    return $url;
}

/**
 * getVariable() returns value of the non-empty variable or false.
 */
function getVariable($var) {
    return !empty($var) ? $var : false;
}

/**
 * getStdin() return standard input or false.
 */
function getStdin() {
    $input  = false;
    $infile = fopen("php://stdin", "r");

    while(!feof($infile))
        $input = $input . fgets($infile, 4096);

    return $input;
}

/**
 * getMetadata() returns a link to metadata (either in $_POST["link"] or
 * $_GET["link"]) or a metadata file ($_FILES["file"]).
 */
function getMetadata() {
    if(isGet()) {
        $link = @getVariable($_GET["link"]);

        if(!$link)
            throw new Exception("No metadata URL defined in HTTP GET variable `link`.");

        return validateURL($link);
    }

    if(isPost()) {
        $link = @getVariable($_POST["link"]);
        $file = $_FILES["file"];

        if((empty($link) && $file["size"] === 0))
            throw new Exception("Neither metadata URL defined nor metadata file selected.");

        elseif(!empty($link) && $file["size"] > 0)
            throw new Exception("Either define metadata URL or select metadata file, not both.");

        elseif(!empty($link)) {
            validateURL($link);
            return $link;
        }

        elseif($file["size"] > 0)
            return $file["tmp_name"];
        }

    return false;
}

