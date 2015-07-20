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
            $("#sts_pre").html($sts_as_bash);
            break;
        case "json":
            $("#sts_pre").html($sts_as_json);
            break;
        case "saml":
            $("#sts_pre").html($saml);
            break;
        }

}
    </script>
  </head>

  <body>

    <div class="container">
      <div class="header clearfix">
        <nav>
          <ul class="nav nav-pills pull-right">
            <li id="bash" role="presentation" class="active"><a href="javascript:format_content('bash')">bash</a></li>
            <li id="json" role="presentation"><a href="javascript:format_content('json')">json</a></li>
<?php if (FullSAMLAssertionAndResponseAvailable == true) { ?>
<li id="saml" role="presentation"><a href="javascript:format_content('binary')">(debug)</a></li>
<?php } ?>
          </ul>
        </nav>
        <h3 class="text-muted">STS Dispenser</h3>
      </div>

      <div class="jumbotron">

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
    $client = StsClient::factory(array(
        'region' => 'us-east-2',
        'version' => 'latest')
    );

    print   "<h2>Your STS Token</h2>";
    $saml=$_POST['SAMLResponse'];
    if(FullSAMLAssertionAndResponseAvailable == true){
        print "<script>var IdP_assertion=${base64_decode($_POST['SAMLResponse'])}</script>";
    }
$result = $client->assumeRoleWithSAML(array(
    // TODO: make role to assume variable, of course. May need to take it from the saml 
    // assertion that is coming from the IdP.
    'RoleArn' => 'arn:aws:iam::556247969450:role/STSasIdPAssume',
    'PrincipalArn' => 'arn:aws:iam::556247969450:saml-provider/STSTokenProvierAsIdP',
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
$sts_as_bash += "export AWS_SECRET_ACCESS_KEY=" . $result['Credentials']['SecretAccessKey'] . "\n";
$sts_as_bash += "export AWS_SECURITY_TOKEN=" . $result['Credentials']['SessionToken'] . "\n";
print	"<pre id=\"sts_pre\">";
    $sts_as_json = json_encode($result['Credentials']['AccessKeyId'] );

print	"<pre id=\"sts_pre\">";
//print $result;
$credentials = $result->get('Credentials');
$session_token     = $credentials['SessionToken'];
$access_key_id     = $credentials['AccessKeyId'];
$secret_access_key = $credentials['SecretAccessKey'];

$credentials_obj = $client->createCredentials($result);
$iam_client = IamClient::factory(array( 
	    'credentials' => $credentials_obj,
            'region' => 'us-east-1',
	    'version' => '2010-05-08'
	    ));

// $iam_client = IamClient::factory(array( 
//        'key' => $access_key_id,
//        'secret' => $secret_access_key,
//        'token' => $session_token,
//        'region' => 'us-east-1',
//        'version' => '2010-05-08'
//        )); 

$response = $iam_client->listPolicies(array('OnlyAttached' => true));
//print "<br/>This token allows you to execute calls allowed by the policy " . $result['Credentials']['Expiration'] . "(". $diff ." minutes)";
}

} catch (Exception $e) {

//print $e;
   print "<br/><br/> If you have trouble reloading this page.  <a href=\"https://ec2-52-4-120-194.compute-1.amazonaws.com/saml/module.php/saml/disco.php?entityID=https%3A%2F%2Fec2-52-4-120-194.compute-1.amazonaws.com%2Fsaml%2Fmodule.php%2Fsaml%2Fsp%2Fmetadata.php%2FSTSDispenser-SP&return=https%3A%2F%2Fec2-52-4-120-194.compute-1.amazonaws.com%2Fsaml%2Fmodule.php%2Fsaml%2Fsp%2Fdiscoresp.php%3FAuthID%3D_e6c6daf549e961f61680f96a8d604e308124f4df4a%253Ahttps%253A%252F%252Fec2-52-4-120-194.compute-1.amazonaws.com%252Fsaml%252Fmodule.php%252Fcore%252Fas_login.php%253FAuthId%253DSTSDispenser-SP%2526ReturnTo%253Dhttps%25253A%25252F%25252Fec2-52-4-120-194.compute-1.amazonaws.com%25252Fsaml%25252Fmodule.php%25252Fcore%25252Fauthenticate.php%25253Fas%25253DSTSDispenser-SP&returnIDParam=idpentityid\">Start at your Identity Provider.</a>";
   exit();

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
