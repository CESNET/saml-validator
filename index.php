<?php

require_once(dirname(__FILE__) . "/functions.php");
require_once(dirname(__FILE__) . "/validator.php");

?>
<!DOCTYPE html>
<!--[if lt IE 7]>      <html class="no-js lt-ie9 lt-ie8 lt-ie7"> <![endif]-->
<!--[if IE 7]>         <html class="no-js lt-ie9 lt-ie8"> <![endif]-->
<!--[if IE 8]>         <html class="no-js lt-ie9"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js"> <!--<![endif]-->
<head>
    <meta charset="utf-8">
    <!--[if IE]>
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <![endif]-->
    <title>SAML-validator [eduID.cz]</title>
    <meta name="description" content="">
    <meta name="viewport" content="width=device-width">
    <link href="https://fonts.googleapis.com/css?family=Oswald&amp;subset=latin,latin-ext" rel="stylesheet" type="text/css">

    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="stylesheet" href="css/main.css">
    <link rel="stylesheet" href="css/style.css">

    <script src="js/vendor/modernizr-2.6.2-respond-1.1.0.min.js"></script>

    <link rel="shortcut icon" href="../img/favicon.ico">
    <link rel="apple-touch-icon" href="../img/apple-touch-icon.png">
</head>
<body>
    <div class="sr-only"><a href="#content">Přeskočit na obsah</a></div>

    <div id="cesnet_linker_placeholder"
        data-lang="cs"
        data-lang-cs-href="?lang=cs"
        data-lang-en-href="?lang=en"
        data-dimensions-brand-width="283"
        data-dimensions-brand-gap="9"
        data-dimensions-max-width="1170">
        <noscript>
        <div class="cl_actions">
            <a href="?lang=cs"><img alt="česká vlajka" src="data:image/gif;base64,R0lGODlhEgANALMAADV4zfLy8s3NzUiCz+cAAJ2dnexvbbfN6+3t7d4AAPj4+N/f3+hfXZIzXKK/5MFZbSH5BAAAAAAALAAAAAASAA0AAARNsMhJKx0H6b26X4I0YEpplkEahMU4OKeiBsgqujCqbqw7ALDZBtFzAQAPg9LAaDJvP0CDQE1Yr4nbcUolYK9abvVrvTXIaNEZTba4LREAOw=="></a>
            <a href="?lang=en"><img alt="english flag" src="data:image/gif;base64,R0lGODlhEgANALMAAPv7+wAAPPsAAAUVh52dnfZgVXOQxU50qyhNp6Zxmb/I4qOx1/iPjVRuwXMQKdOi0CH5BAAAAAAALAAAAAASAA0AAARtkMhJKz3roK2cU0OIOIdkMIBiGEBRAE2zvIaELAzaAIIAM7SBzdB4vHi+FwgRkCgA0GgvGlVIHIWedrt1OKnQKdhKGDQGT59YkAg1yywXAgkYtASNd3yxoYcWPAgSBw4hAwEdHwGLAQZvFpAUEQA7"></a>
            Přihlášení:
            [ <a href="/Shibboleth.sso/Login"><strong>eduID.cz</strong></a>
            ] [
            <a href="/cztestfed/Shibboleth.sso/Login">czTestFed</a>
            ]
        </div>
        Nemáte povolený JavaScript. Přehled služeb e-infrastruktury CESNET získáte na stránce: <a href="http://cesnet.cz/sluzby">http://cesnet.cz/sluzby</a>.
        </noscript>
    </div>

    <div id="wrap">
        <div class="container">
            <!--[if lt IE 7]><div class="row"><p class="chromeframe">You are using an <strong>outdated</strong> browser. Please <a href="http://browsehappy.com/">upgrade your browser</a> or <a href="http://www.google.com/chromeframe/?redirect=true">activate Google Chrome Frame</a> to improve your experience.</p></div><![endif]-->
            <div class="row">

                <div id="sidebar" class="col-md-3 col-sm-4">

                    <div class="logo-wrapper">
                        <a href="/">
                            <img src="img/logo.svg" id="logo" class="img-responsive" alt="logo">
                        </a>
                    </div>

                </div> <!-- /#sidebar -->

                <div id="content" class="col-md-9 col-sm-8">

                    <h1 class="page-header">SAML-validator</h1>
                    <div class="row">
                      <div class="col-lg-12">
<!--
                        <h2 id="type">Typography</h2>
-->
                        <p>
                        This is a PHP tool to validate SAML metadata for compliance with <a href="https://www.eduid.cz">eduID.cz</a> federation rules.
                        </p>

                        <div class="dropdown" style="position: fixed; top: 2.35em; right: 2em;">
                            <button id="logginbutton" class="btn btn-link dropdown-toggle" type="button" data-toggle="dropdown" style="display: none"></button>
                            <ul class="dropdown-menu dropdown-menu-right">
                                <li class="dropdown-header">Použít federaci:</li>
                                <li><a href="/Shibboleth.sso/Login"><strong>eduID.cz</strong></a></li>
                                <li><a href="/cztestfed/Shibboleth.sso/Login">czTestFed</a></li>
                            </ul>
                        </div>

                      </div>
                    </div>

                </div>

            </div> <!-- /.row -->

            <div class="row">
                <div class="col-lg-12 col-md-12 col-sm-12">

                    <p>You can either upload a metadata file or insert a metadata URL address in
                    the form bellow and click <em>Validate metadata</em> button to get result.</p>

<?php if(isPost()): ?>
<?php

try {
    $result = validateMetadata(getMetadata());
    $alertType = "danger";
    switch($result["result"]) {
        case 0:
            $alertType = "success";
            break;
        case 1:
            $alertType = "warning";
            break;
        case 2:
            $alertType = "danger";
            break;
    }
?>
                    <div class="row">
                      <div class="col-lg-12">
                        <div class="bs-component">
                          <div class="alert alert-<?=$alertType?>">
                            <p>
                                <strong>Validation result:</strong> <em><?=$result["resultText"]?></em>
                            </p>
                            <p>
<?php

if(!empty($result["warning"]))
    echo $result["warning"];

if(!empty($result["error"]))
    echo $result["error"];

?>
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
<?php
} catch(Throwable $t) {
    echo "<p><strong>Caught Exception: ", $t->getMessage(), "</strong></p>\n";
} catch(Exception $e) {
    echo "<p><strong>Caught Exception: ", $e->getMessage(), "</strong></p>\n";
}

?>
<?php endif; ?>

                    <div class="row">
                        <div class="col-sm-12">
                            <div class="well bs-component">
                                <form class="form-horizontal" action="." method="post" enctype="multipart/form-data">
                                    <fieldset>
                                        <legend>Validate SAML metadata</legend>
                                        <div class="form-group">
                                            <label class="col-sm-3 control-label" for="link">Insert metadata URL:</label>
                                            <div class="col-sm-9">
                                                <input type="url" name="link" id="link" style="width: 100%" placeholder="URL address must be HTTPS" autofocus>
                                            </div>
                                        </div>
                                        <div class="form-group">
                                            <label class="col-sm-3 control-label" for="file">Choose metadata file:</label>
                                            <div class="col-sm-9">
                                                <input type="file" accept="text/xml" name="file" id="file">
                                            </div>
                                        </div>
                                        <div class="form-group">
                                            <div class="col-sm-9 col-sm-offset-3">
                                                <button type="submit" name="submit" class="btn btn-danger">Validate metadata</button>
                                            </div>
                                        </div>
                                    </fieldset>
                                </form>
                            </div>
                        </div>
                    </div>

                    <div class="row">
                      <div class="col-lg-12">
                        <div class="bs-component">
                          <div class="alert alert-info">
                            <p>
                                <strong>Tip:</strong> Default metadata location:
                            </p>
                            <ul class="metadata-tip">
                                <li>Shibboleth IdP: <code>https://example.org/idp/shibboleth</code></li>
                                <li>Shibboleth SP: <code>https://example.org/Shibboleth.sso/Metadata</code></li>
                                <li>SimpleSAMLphp: <code>https://example.org/simplesaml/module.php/saml/sp/metadata.php/default-sp</code></li>
                            </ul>
                          </div>
                        </div>
                      </div>
                    </div>

                </div>
            </div>

        </div> <!-- /.container -->

        <div id="push"></div> <!-- for footer -->
    </div> <!-- /#wrap -->

    <div id="footer"><footer><div class="container">
        <div class="row">
            <div class="col col-md-3">
                <div class="logo-wrapper"><img src="img/logo-cesnet.svg" class="img-responsive" alt="cesnet logo"></div>
            </div>
            <div class="col-lg-7 col-lg-push-2 col-md-push-1 col-md-8">
                <div class="row">
                    <div class="col col-sm-4">
                        <h2>Rychlé odkazy</h2>
                        <ul>
                            <li><a href="#">CESNET PKI</a></li>
                            <li><a href="#">eduID.cz</a></li>
                            <li><a href="#">eduroam</a></li>
                            <li><a href="#">MetaCentrum</a></li>
                            <li><a href="#">PERUN</a></li>
                        </ul>
                    </div>
                    <div class="col col-sm-4">
                        <h2>Kontakt</h2>
                        CESNET, z. s. p. o.<br/>
                        ZIKOVA 4, 16000 PRAHA <br/>
                        TEL : +420 224 352 994<br/>
                        FAX : +420 224 320 269<br/>
                        <a href="mailto:info@cesnet.cz">info@cesnet.cz</a>
                    </div>
                    <div class="col col-sm-4">
                        <h2>Stálá služba</h2>
                        TEL: +420 224 352 994<br/>
                        GSM: +420 602 252 531<br/>
                        FAX: +420 224 313 211<br/>
                        <a href="mailto:support@cesnet.cz">support@cesnet.cz</a>
                    </div>
                </div>
            </div>
        </div>
        <div class="row">
            <div class="col col-sm-12 copyright">
                © 1996–2014 CESNET, z. s. p. o.
            </div>
        </div>
    </div></footer></div>

    <script src="//code.jquery.com/jquery-latest.min.js"></script>
    <script>if (!window.jQuery) document.write('<script src="js/vendor/jquery-1.11.1.min.js"><\/script>');</script>
    <script src="js/vendor/bootstrap.min.js"></script>
    <script src="js/main.js"></script>
    <script type="text/javascript" async src="https://linker2.cesnet.cz/linker.js"></script>

</body>
</html>
