<?php 
require("../config.php"); 
require("../idp_config.php"); 
require '../vendor/autoload.php';
# TODO: check health of metadata 
use Aws\Sts\StsClient;
use Aws\Iam\IamClient;
?>

<!DOCTYPE html>
<html lang="en">
  <head>

    <title>STS Token Dispenser</title>    
<?php
    $method = $_SERVER['REQUEST_METHOD'];

if ($method != "POST"  && AUTO_INITIATE) {
?>
<meta http-equiv="refresh" content="<?php echo  REDIRECT_DELAY;?>;URL='<?php echo IDP_SSO_URL;?>?SAMLRequest=<?php  echo generateAuthnRequest();?>'/>
<?php
}
?>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="STS Dispenser, A SAML 2.0 SP used to provided AWS STS tokens via a web page.">
    <meta name="author" content="Fabio Arciniegas fab.arciniegas@gmail.com">
    <link rel="icon" href="../../favicon.ico">
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
    <link href="sts_dispenser.css" rel="stylesheet">
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/zeroclipboard/2.2.0/ZeroClipboard.js"></script>

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->

    <script>
      var sts = "(no token available)";                                                                  
      function format_content(f){
        $( "li[class|=active]" ).removeClass( "active" );
        var li = $( "#"+f ).addClass( "active" );

        switch (f) {
        case "bash":
            $("#sts_pre").html(sts_as_bash);
            break;
        case "json":
            $("#sts_pre").html(JSON.stringify(sts_as_json));
            break;
        case "debug":
            $("#sts_pre").html(sts_as_debug);
            break;
        }
}
    function adjust_ui_to_result(){
	if(typeof valid_token_acquired == 'undefined') {
         	$("#greeting").addClass( "gray");
                $("#button_text").removeClass( "btn");
                $("#button_text").removeClass( "btn-success");
                $("#button_text").addClass( "btn-warning");
        }
        else{
	    format_content('bash');
        }
     }

    </script>
  </head>

  <body onload="adjust_ui_to_result()">

    <div class="container">
      <div class="header clearfix">
        <nav>
          <ul class="nav nav-pills pull-right">
            <li id="bash" role="presentation" class="active"><a href="javascript:format_content('bash')">bash</a></li>
            <li id="json" role="presentation"><a href="javascript:format_content('json')">json</a></li>
<?php if (DEBUG_SAML == true) { ?>
<li id="debug" role="presentation"><a href="javascript:format_content('debug')">saml</a></li>
<?php } ?>
<?php if (PRESENT_LOGOUT == true) { ?>
<li id="logout" role="presentation"><a href="<?php echo IDP_SLO_URL; ?>">(logout)</a></li>
<?php } ?>
          </ul>
        </nav>
        <h3 class="text-muted">STS Dispenser</h3>
      </div>
      <div class="jumbotron">
          <h2 id="greeting">Your STS Token</h2>


      <pre id="sts_pre"></pre>
<!-- *************************************************
     STS LOGIC
     ************************************************* -->

<?php

try {
    if ($method != "POST") {
    print "To receive a token you must  authenticate.";
   $ls_template= "<div id=\"warn\" class=\"warning\">You are now being redirected to <a href=\"%s?SAMLRequest=%s\">%s</a></div>";
        if (AUTO_INITIATE) {
         print sprintf($ls_template,IDP_SSO_URL,generateAuthnRequest(),IDP_DISPLAY_NAME);
        }
    }
    else {
    #TODO: config region
    $client = StsClient::factory(array(
        'region' => 'us-east-2',
        'version' => 'latest'));

#TODO check that the response contains a SAMLRESPONSE first
    $assertion = decodeSAMLResponse($_POST['SAMLResponse']);

    $assertion_xml = simplexml_load_string($assertion);
    $sts_as_debug= $assertion; 
    print	"<script>var sts_as_debug=\"". str_replace("\n"," ",htmlspecialchars($assertion)) . "\";</script>";

    if($assertion_xml == false){
         throw new Exception("Malformed response received. This is likely a problem in the IdP.<br/>You can turn on debug to examine the response but it is not likely to be something you can fix at this end of the federation.");
    }
    $saml_ns = $assertion_xml->children('urn:oasis:names:tc:SAML:2.0:assertion');
#    print htmlspecialchars($saml_ns->asXML());
#    $role_arn = $saml_ns->Assertion->AttributeStatement->Attribute;
#     $role_arn = $saml_ns->Assertion->AttributeStatement->Attribute->xpath('.[@Name=\"https://aws.amazon.com/SAML/Attributes/Role\"]');
    $saml_ns->registerXPathNamespace ('s','urn:oasis:names:tc:SAML:2.0:assertion');
    $assertion_roles = $saml_ns->xpath('//s:Assertion/s:AttributeStatement/s:Attribute[@Name=\'https://aws.amazon.com/SAML/Attributes/Role\']/s:AttributeValue');
    $user_id = $saml_ns->xpath('//s:Assertion/s:AttributeStatement/s:Attribute[@Name=\'uid\']/s:AttributeValue');
#TODO check that values were actually properly parsed out
#    $role_arn = $saml_ns->xpath('/Assertion/AttributeStatement/Attribute[@Name=\"https://aws.amazon.com/SAML/Attributes/Role\"]');
    $roles = array();
    foreach ($assertion_roles as $r){
      $pieces = explode(",",$r);
      $roles[$pieces[0]]=$pieces[1];
}

    $result = $client->assumeRoleWithSAML(array(
#    // TODO: support multiple roles on dropdown, of course. 
    'RoleArn' => array_keys($roles)[0],
    'PrincipalArn' => $roles[array_keys($roles)[0]],
    'SAMLAssertion' => $_POST['SAMLResponse'],
//    'Policy' => 'string',
    'DurationSeconds' => 3600,
              ));

     $exp = $result['Credentials']['Expiration'];
     $exp2 = strtotime($exp);
     $current_time = time();
     $diff = round(($exp2 - $current_time)/60,2);
     print "<p class=\"lead\"> Will be valid until  ". $result['Credentials']['Expiration'] . "(". $diff ." minutes)"."	</p>";

     $sts_as_bash = "export AWS_ACCESS_KEY_ID=" . $result['Credentials']['AccessKeyId'] . "\n";
     $sts_as_bash = $sts_as_bash . "export AWS_SECRET_ACCESS_KEY=" . $result['Credentials']['SecretAccessKey'] . "\n";
     $sts_as_bash = $sts_as_bash . "export AWS_SECURITY_TOKEN=" . $result['Credentials']['SessionToken'] . "\n";
     $sts_as_json = json_encode($result['Credentials'] );


     print	"<script>var sts_as_bash=\"". str_replace("\n",";",$sts_as_bash) . "\";</script>";

#TODO: verify output is complete (chrome)
     print	"<script>var sts_as_json=". $sts_as_json . ";</script>";
     print	"<script>var sts_as_debug=\"". str_replace("\n"," ",htmlspecialchars($sts_as_debug)) . "\";</script>";





// $credentials = $result->get('Credentials');
// $session_token     = $credentials['SessionToken'];
// $access_key_id     = $credentials['AccessKeyId'];
// $secret_access_key = $credentials['SecretAccessKey'];

// #$credentials_obj = $client->createCredentials($result);
// $iam_client = IamClient::factory(array( 
// 	    'credentials' => $credentials_obj,
//         'region' => 'us-east-1',
// 	    'version' => '2010-05-08'
// 	    ));

     print	"<script>var valid_token_acquired=true;</script>";
// $response = $iam_client->listPolicies(array('OnlyAttached' => true));
//print "<br/>This token allows you to execute calls allowed by the policy " . $result['Credentials']['Expiration'] . "(". $diff ." minutes)";
}

} catch (\Aws\Sts\Exception\ExpiredTokenException $e) {
    print "Token expired. Note that an STS ticket must be redeemed within 5 minutes of issuance.<br/>";
   $ls_template= "<div id=\"warn\" class=\"warning\">Click on this link to <a href=\"%s?SAMLRequest=%s\">%s</a> to receive a new one.</div>";
   print sprintf($ls_template,IDP_SSO_URL,generateAuthnRequest(),IDP_DISPLAY_NAME);
}
catch (Exception $e) {
    print $e->getMessage();
}
?>
	</pre>

<?php
if ($method == "POST") {
?>
	<p><a data-clipboard-target="sts_pre" id="button_text" class="btn btn-lg btn-success" href="#" role="button">Copy to clipboard</a></p>
    <script type="text/javascript">
      var client = new ZeroClipboard(document.getElementById('button_text'));
    </script>

<?php
}
?>
      </div>

<div align="right"><a data-toggle="collapse" data-target="#help_text" href="#" > help &gt;&gt</a></div>

      <div id="help_text" class="collapse">
      <div class="row marketing" >

        <div class="col-lg-6">
          <h4>What is an STS token?</h4>
<p>Temporary credentials you can use instead of hard-coding your actual secret key/access key on a script. The easiest way to use it is to copy paste the values as bash environment variables and start running aws cli commands.</p>

          <h4>What is this page?</h4>
          <p>A SAML 2.0 Service Provider, which serves AWS STS tokens. In other words is a helper app that gives you temporary credentials to make AWS calls. It is the result of authenticating with your enterprise credentials instead of using AWS long-term credentials associated with a user.</p>

          <h4>Why is it useful?</h4>
AWS federation is commonly understood as loggin in to AWS console by authenticating through Active Directory. Some people would like extend that federation model to additionally make CLI and API calls. Instead of using long-term access keys (and worrying about their safety), the user can make calls using the temporary credentials above. Using this extended form of federation an organization can reduce the number of credentials provisioned inside AWS and instead manage authentication on its own (e.g. exclusively inside Active Directory, without ever provisioning passwords or keys to users inside AWS.)</p>

	</div>

        <div class="col-lg-6">
<!--          <h4>Why use it?</h4>
          <p>If you have a working AWS federation (e.g. with ADFS), and want to make AWS CLI/API calls authenticating through AD instead of authenticating wih AWS-provided access keys.</p>
-->

          <h4>Usage Demo video</h4>
          <p>You can watch a simple demo video here. For more detailed information on implementation and configuration see the help page.</p>

          <h4>Quick Configuration</h4>
          <p>Add this <a href="metadata.xml">metadata</a> to your ADFS or similar iDP to add the STS Dispenser as a service provider</p>. For more see the documentation folder.</p>
        </div>

      </div>
      </div>
      <footer class="footer">
        <p class="copyright">&copy; Fabio Arciniegas, Trend Micro 2015</p>
      </footer>

    </div> <!-- /container -->

    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug 
    <script src="../../assets/js/ie10-viewport-bug-workaround.js"></script>
-->

  </body>
</html>
