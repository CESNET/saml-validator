<?php 

if(preg_match("/cs|sk/", $_SERVER["HTTP_ACCEPT_LANGUAGE"])) {
    $locale = "czech";
} else {
    $locale = "english";
}

?>
<!DOCTYPE html>

<html>
<head>
    <title>SAML-validator</title>
    <meta charset="utf-8">
    <meta name="Author" content="Jan Oppolzer; jan@oppolzer.cz">
    <link rel="stylesheet" type="text/css" href="css/normalize.css">
    <link rel="stylesheet" type="text/css" href="css/style.css">
</head>
<body>

<?php

switch($locale) {
    // Czech
    case "czech":
?>
<h1>SAML-validátor</h1>

<p>Tato PHP aplikace otestuje SAML metadata na shodu s pravidly federace <a
href="https://www.eduid.cz">eduID.cz</a>.</p>

<p>Metadata můžete buď nahrát jako soubor anebo vložit jejich URL adresu a
kliknout na tlačítko <em>Validovat metadata</em> pro získání výsledku.</p>

<p>Jelikož je primárním účelem této aplikace pomoci otestovat metadata aplikaci
<a href="https://rr.cesnet.cz/jagger">Jagger</a>, budete přesměrováni na novou
XML stránku a budete-li chtít otestovat další metadata, budete muset kliknout
na tlačítko <em>Zpět</em> ve vašem webovém prohlížeči.</p>

<form action="./upload.php" method="post" enctype="multipart/form-data">
    Soubor s metadaty: <input type="file" accept="text/xml" name="file" id="file"><br>
    URL adresa metadat: <input type="input" name="link" id="link" size="50"><br>
    <input type="submit" value="Validovat metadata" name="submit">
</form>

<hr class="hidden">

<footer>
<p>Pro více informací se podívejte do souboru <a
href="https://github.com/JanOppolzer/saml-validator/blob/master/README.md">README.md</a>
nebo na <a href="https://github.com/JanOppolzer/saml-validator/wiki">Wiki</a>
stránku na GitHubu.</p>
</footer>
<?php
        break;
    // English
    case "english":
    default:
?>
<h1>SAML-validator</h1>

<p>This is a PHP tool to validate SAML metadata for compliance with <a
href="https://www.eduid.cz">eduID.cz</a> federation rules.</p>

<p>You can either upload a metadata file or insert a metadata URL address in
the form bellow and click <em>Validate metadata</em> button to get result.</p>

<p>Since the primary use of this tool is to assist <a
href="https://rr.cesnet.cz/jagger/">Jagger</a> to decide whether a metadata
is valid or not, you will be redirected to a new XML-only page and in order to
test another metadata, you will have to click <em>Back</em> button in your web
browser.</p>

<form action="./upload.php" method="post" enctype="multipart/form-data">
    Choose metadata file: <input type="file" accept="text/xml" name="file" id="file"><br>
    Insert metadata URL: <input type="input" name="link" id="link" size="50"><br>
    <input type="submit" value="Validate metadata" name="submit">
</form>

<hr class="hidden">

<footer>
<p>For more info, see <a
href="https://github.com/JanOppolzer/saml-validator/blob/master/README.md">README.md</a>
or <a href="https://github.com/JanOppolzer/saml-validator/wiki">Wiki</a> page
on GitHub.</p>
</footer>
<?php
        break;
}

?>

</body>
</html>

