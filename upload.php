<?php

/* $UPLOAD_DIR variable defines a directory where to upload the files
 */
$UPLOAD_DIR         = "tmp/";
$ALLOWED_FILE_TYPES = array("text/xml");

/*
 * checkDependencies() checks for required PHP dependencies.
 */
function checkDependencies() {
    if(!extension_loaded(xmlwriter))
        throw new Exception("XMLwritter support not available.");
}

/* checkUploadDir() checks for upload directory
 */
function checkUploadDir($dir) {
    if(!file_exists($dir) || !is_dir($dir)) {
        throw new Exception("$dir directory does not exist.");
    }

    if(!is_writable($dir)) {
        throw new Exception("$dir directory is not writable by web server.");
    }
}

/* fileOrLink() checks if we have a metadata file or a metadata URL
 */
function fileOrLink($file, $link) {
    if(($file["size"] === 0) && (empty($link))) {
        throw new Exception("Neither metadata file nor metadata URL specified.");
    } elseif(($file["size"] > 0) && (!empty($link))) {
        throw new Exception("Either upload metadata file or insert metadata URL, but not both.");
    } elseif($file["size"] > 0) {
        return $file;
    } elseif(!empty($link)) {
        if(filter_var($link, FILTER_VALIDATE_URL, FILTER_FLAG_PATH_REQUIRED)) {
            if(preg_match("/^https\:/", $link)) {
                return $link;
            } else {
                throw new Exception("You have to provide HTTPS URL address.");
            }
        } else {
            throw new Exception("No proper URL address specified.");
        }
    }
}

/* uploadFile() uploads a file to upload directory and returns the URL address
 * of the file
 */
function uploadFile($metadata) {
    if(is_array($metadata)) {
        if($metadata["size"] > 100000) {
            throw new Exception("$metadata[name] exceeded file size limit.");
        }
        if(!file_exists($metadata["tmp_name"])) {
            throw new Exception("$metadata[name] file could not be uploaded.");
        } else {
            if(in_array($metadata["type"], $GLOBALS["ALLOWED_FILE_TYPES"])) {
                $destinationFile = sha1_file($metadata["tmp_name"]) . uniqid("_") . ".xml";

                if(!move_uploaded_file($metadata["tmp_name"], $GLOBALS["UPLOAD_DIR"] . $destinationFile)) {
                    throw new Exception("Failed to move uploaded file.");
                } else {
                    return "https://"
                           . $_SERVER["HTTP_HOST"]
                           . pathinfo($_SERVER["REQUEST_URI"], PATHINFO_DIRNAME)
                           . "/"
                           . $GLOBALS["UPLOAD_DIR"]
                           . $destinationFile
                           . "&d=1";
                }
            } else {
                throw new Exception("Only XML documents allowed.");
            }
        }
    } elseif(is_string($metadata)) {
        return $metadata;
    } else {
        throw new Exception("Neither file nor URL specified.");
    }
}

/* validateMetadata() redirects to the SAML-validator itself
 */
function validateMetadata($metadata) {
    header("Location: https://"
         . $_SERVER["HTTP_HOST"]
         . pathinfo($_SERVER["REQUEST_URI"], PATHINFO_DIRNAME)
         . "/validator.php?filename="
         . $metadata);
}

/* upload file and redirect to the SAML-validator
 */
try {
    checkDependencies();
    checkUploadDir($UPLOAD_DIR);
    validateMetadata(uploadFile(fileOrLink($_FILES["file"], $_POST["link"])));
} catch(Exception $e) {
    echo "Caught exception: ", $e->getMessage(), "\n";
}

?>

