<?php

/* $UPLOAD_DIR variable defines a directory where to upload the files
 */
$UPLOAD_DIR  = "tmp/";

/* checkUploadDir() checks for upload directory
 */
function checkUploadDir($dir) {
    if(!file_exists($dir) || !is_dir($dir)) {
        throw new Exception("$dir directory does not exist.");
    }

    if(!is_writable($dir)) {
        throw new Exception("$dir directory is not writable by web server.");
        # FIXME: try to create $dir
    }
}

/* uploadFile() uploads a file to upload directory and returns the URL address
 * of the file
 */
function uploadFile($file) {
    # FIXME: check mime type of the uploaded file and if not text/xml, don't upload it!
    if(!file_exists($file["tmp_name"])) {
        throw new Exception("$file[name] file could not be uploaded.");
    } else {
        $destinationFile = sha1_file($file["tmp_name"]) . uniqid("_") . ".xml";

        if(!move_uploaded_file($file["tmp_name"], $GLOBALS["UPLOAD_DIR"] . $destinationFile)) {
            throw new Exception("Failed to move uploaded file.");
        } else {
            return "https://"
                   . $_SERVER["HTTP_HOST"]
                   . pathinfo($_SERVER["DOCUMENT_URI"], PATHINFO_DIRNAME)
                   . "/"
                   . $GLOBALS["UPLOAD_DIR"]
                   . $destinationFile;
        }
    }
}

/* validateMetadata() redirects to the SAML-validator itself
 */
function validateMetadata($metadata) {
    header("Location: https://"
         . $_SERVER["HTTP_HOST"]
         . pathinfo($_SERVER["DOCUMENT_URI"], PATHINFO_DIRNAME)
         . "/validator.php?filename="
         . $metadata);
}

/* upload file and redirect to the SAML-validator
 */
try {
    checkUploadDir($UPLOAD_DIR);
    validateMetadata(uploadFile($_FILES["metadata"]));
} catch(Exception $e) {
    echo "Caught exception: ", $e->getMessage(), "\n";
}

# FIXME:
# uploaded files are left within $UPLOAD_DIR even after SAML validations
# add "deleteAfterCheck" variable to validator.php?

?>

