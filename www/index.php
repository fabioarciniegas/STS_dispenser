<?php 
require("../config.php"); 
require("../idp_config.php"); 
require '../vendor/autoload.php';

use Aws\Sts\StsClient;
use Aws\Iam\IamClient;

?>

<!DOCTYPE html>
<html lang="en">
  <head>

    <title>STS Token Dispenser</title>    
<?php
     $token_acquired = 0;
    $method = $_SERVER['REQUEST_METHOD'];

if ($method != "POST"  && AUTO_INITIATE) {
    if(!IDP_INITIATED_ONLY) {
?>

<meta http-equiv="refresh" content="<?php echo  REDIRECT_DELAY;?>;URL='<?php echo IDP_SSO_URL;?>?SAMLRequest=<?php  echo generateAuthnRequest();?>'/>
<?php
}
     else {
?>
<meta http-equiv="refresh" content="<?php echo  REDIRECT_DELAY;?>;URL='<?php echo STATIC_IDP_INITIATION_URL;?>'/>
<?php
}
}
?>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="STS Dispenser, A SAML 2.0 SP used to provided AWS STS tokens via a web page.">
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

      var sts = "(no token available)";                                                  var current_format = 'none'
      var current_role  = 'none';                      

      function format_content(f,r){
	if(f == null){      	f = current_format;	}
	if(r == null){      	r = current_role;	}

        $( "li[class|=active]" ).removeClass( "active" );
        var li = $( "#"+f ).addClass( "active" );


        $( "#button_"+current_role ).removeClass( "active" );
        $( "#button_"+r ).addClass( "active" );



        switch (f) {
        case "bash":
            $("#sts_pre").html(sts_as_bash[r]);
            break;
        case "json":
            $("#sts_pre").html(JSON.stringify(sts_as_json[r]));
            break;
        case "debug":
            $("#sts_pre").html(sts_as_debug['__raw_idp_assertion__']);
            break;
        }
        current_format = f;
        current_role = r;
    }
    function adjust_ui_to_result(){
	if(typeof valid_token_acquired == 'undefined') {
         	$("#greeting").addClass( "gray");
                $("#button_text").removeClass( "btn");
                $("#button_text").removeClass( "btn-success");
                $("#button_text").addClass( "btn-warning");
        }
        else{
	    format_content(null,null);
        }
     }

      var sts_as_json =[];
      var sts_as_bash =[];
      var sts_as_debug =[];
    </script>
  </head>

  <body onload="adjust_ui_to_result()">

    <div class="container">
      <div class="header clearfix">
        <nav>
          <ul class="nav nav-pills pull-right">
            <li id="bash" role="presentation" class="active"><a href="javascript:format_content('bash',null)">bash</a></li>
            <li id="json" role="presentation"><a href="javascript:format_content('json',null)">json</a></li>
<?php if (DEBUG_SAML == true) { ?>
<li id="debug" role="presentation"><a href="javascript:format_content('debug',null)">saml</a></li>
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
$all_tokens_one_bash = "";
$all_tokens_one_json = "[";
try {
    if ($method != "POST") {
    print "To receive a token you must be authenticated with your identity provider (e.g. ADFS)";

        if (SHOW_INITIATION_LINK_ON_GET) {
         if(IDP_INITIATED_ONLY){
         $ls_template= "<div id=\"warn\" class=\"warning\">You are now being redirected to <a href=\"%s\">%s</a></div>";
         print sprintf($ls_template,STATIC_IDP_INITIATION_URL,IDP_DISPLAY_NAME);
         } else{
         $ls_template= "<div id=\"warn\" class=\"warning\">You are now being redirected to <a href=\"%s?SAMLRequest=%s\">%s</a></div>";
         print sprintf($ls_template,IDP_SSO_URL,generateAuthnRequest(),IDP_DISPLAY_NAME);
         }
        }
    }
    else {
    $client = StsClient::factory(array(
             'region' => STS_CLIENT_REGION,
             'version' => 'latest'));

    $assertion = decodeSAMLResponse($_POST['SAMLResponse']);
#    file_put_contents("/var/www/STS_dispenser/static.saml",$_POST['SAMLResponse']);

    if(READ_RESPONSE_FILE_INSTEAD){
         error_log("reading from static saml");
         $assertion = file_get_contents(RESPONSE_FILE);
    }

    $assertion_xml = simplexml_load_string($assertion);
    $sts_as_debug['__raw_idp_assertion__']= $assertion; 
    print	"<script>sts_as_debug['__raw_idp_assertion__']=\"". str_replace("\n"," ",htmlspecialchars($sts_as_debug['__raw_idp_assertion__'])) . "\";</script>";

    if($assertion_xml === false){
         throw new Exception("Malformed response received. This is likely a problem in the IdP.<br/>You can turn on debug to examine the response but it is not likely to be something you can fix at this end of the federation.");
    }
    $saml_ns = $assertion_xml->children('urn:oasis:names:tc:SAML:2.0:assertion');
    $saml_ns->registerXPathNamespace ('s','urn:oasis:names:tc:SAML:2.0:assertion');
    $assertion_roles = $saml_ns->xpath('//s:Assertion/s:AttributeStatement/s:Attribute[@Name=\'https://aws.amazon.com/SAML/Attributes/Role\']/s:AttributeValue');
    $user_id = $saml_ns->xpath('//s:Assertion/s:AttributeStatement/s:Attribute[@Name=\'uid\']/s:AttributeValue');

    foreach ($assertion_roles as $r){
      $pieces = explode(",",$r);
      $arn_pieces = array();
      preg_match("/.*::(\d+).*\/(.+)/",$pieces[1],$arn_pieces);
      $short_role = $arn_pieces[2]."_".$arn_pieces[1];

      try {
       
      $current_token = $client->assumeRoleWithSAML(array(
                                      'RoleArn' => $pieces[1],
                                       'PrincipalArn' => $pieces[0],
                                       'SAMLAssertion' => $_POST['SAMLResponse'],
                                        //    'Policy' => 'further_restrictions_if_desired',
                                       'DurationSeconds' => 3600));



       $iamClient = IamClient::factory([
                  'credentials' => $client->createCredentials($current_token),
                  'version' => 'latest']);
       $account_alias = $iamClient->listAccountAliases();


$bashTemplate = <<<BASH_TEMPLATE
export AWS_ACCESS_KEY_ID="%s"; 
export AWS_SECRET_ACCESS_KEY="%s"; 
export AWS_SECURITY_TOKEN="%s"; 
BASH_TEMPLATE;

      if(count($account_alias['AccountAliases']) > 0){ 
         $short_role = $arn_pieces[2]."_".$account_alias['AccountAliases'][0];
      }

     $result[$short_role] = $current_token;
     $sts_as_bash[$short_role] = sprintf($bashTemplate,
                                         $result[$short_role]['Credentials']['AccessKeyId'],
                                         $result[$short_role]['Credentials']['SecretAccessKey'],
                                         $result[$short_role]['Credentials']['SessionToken']);


     $sts_as_json[$short_role] = json_encode($result[$short_role]['Credentials'] );


$all_tokens_template = <<<AGGREGATE_BASH_TEMPLATE
STS_KEYS[%d]="%s";
STS_SECRETS[%d]="%s";
STS_TOKENS[%d]="%s";
STS_ALIASES[%d]="%s";

AGGREGATE_BASH_TEMPLATE;

$all_tokens_one_bash = $all_tokens_one_bash . sprintf($all_tokens_template,
                    $token_acquired,$result[$short_role]['Credentials']['AccessKeyId'],
                    $token_acquired,$result[$short_role]['Credentials']['SecretAccessKey'],
                    $token_acquired,$result[$short_role]['Credentials']['SessionToken'],
                    $token_acquired,$short_role
);

$all_tokens_one_json = $all_tokens_one_json . json_encode($result[$short_role]['Credentials']) . ",";
     $token_acquired++;


    } catch (Exception $e) {
     $sts_as_bash[$short_role] = "#Token for this account/role (".$pieces[1].") could not be acquired.";
     $sts_as_json[$short_role] = "\"Token for this account/role (".$pieces[1].") could not be acquired.\"";

    error_log($e->getMessage());
     }
    finally {
        print	"\n<script>sts_as_bash[\"{$short_role}\"]=". json_encode($sts_as_bash[$short_role]) . "</script>";
        print	"\n<script>sts_as_json[\"{$short_role}\"]=". $sts_as_json[$short_role] . ";</script>\n";
    }

}

   if ($token_acquired === 0){          
      throw new Exception("An assertion was received but no token from it could be acquired.");
   }

     $sts_as_bash['All_All'] = $all_tokens_one_bash;
     print	"<script>sts_as_bash['All_All']=". json_encode($all_tokens_one_bash) . ";</script>";

     $all_tokens_one_json = $all_tokens_one_json . "]";
     $sts_as_json['All_All'] = $all_tokens_one_json;
     print	"<script>sts_as_json['All_All']=". $all_tokens_one_json . ";</script>";



     print	"<script>current_format = 'bash'</script>";
     print	"<script>current_role  = '".array_keys($sts_as_bash)[0]."'</script>";
     print	"<script>var valid_token_acquired=true;</script>";

} 
}catch (Exception $e) {
    error_log($e->getMessage());
    print "No tokens at all available (".count(array_keys($sts_as_bash))." roles tried). Your assertion may have expired.<br/>";


    if (SHOW_INITIATION_LINK_ON_ERROR) {
       if (!IDP_INITIATED_ONLY){
          $ls_template= "<div id=\"warn\" class=\"warning\">Click on this link to <a href=\"%s?SAMLRequest=%s\">%s</a> to receive a new one.</div><br/>";
          print sprintf($ls_template,IDP_SSO_URL,generateAuthnRequest(),IDP_DISPLAY_NAME);
        }
       else {
          $ls_template= "<div id=\"warn\" class=\"warning\">Click on this link to <a href=\"%s\">%s</a> to receive a new one.</div><br/>";
          print sprintf($ls_template,STATIC_IDP_INITIATION_URL,IDP_DISPLAY_NAME);
       }
    }
}
?>
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
<?php
     if($token_acquired && count(array_keys($sts_as_bash)) > 1){
?>
You are authorized to assume more than one role. Choose role below to update token: <br/>
<div class="btn-group btn-group-xs" role="group" >

<?php
   $button_cnt =0;
   $previous_account = "none";
     foreach (array_keys($sts_as_bash) as $r){
      $account = after_last("_",$r);
      if($account != $previous_account){
          print "<br/><h3>".htmlspecialchars($account)."</h3>";
          $previous_account = $account;      
      }
?>


  <button class="btn btn-default btn-xs role_button" id="button_<?php echo $r?>" onClick="format_content(null,'<?php echo array_keys($sts_as_bash)[$button_cnt]?>')">
    <?php echo before_last("_",array_keys($sts_as_bash)[$button_cnt++])?>
  </button>

<?php
}
?>
</div>
<?php
}
?>

<br/>

<div align="right"><a data-toggle="collapse" data-target="#help_text" href="#" > Usage Guide/Help &gt;&gt</a></div>

      <div id="help_text" class="collapse">
      <div class="row marketing" >

        <div class="col-lg-6">
          <h3>FAQs</h3>
          <h4>What is this?</h4>
          <p>An app that gives you temporary credentials (STS token) to make Amazon Web Services (AWS) calls after authenticating with your enterprise credentials.</p>

          <h4>What is an STS token? What is AWS CLI?</h4>
          <p>A temporary token you can use to make authenticated calls to Amazon Web Services, for example using the command line tools provided by Amazon.</p>

          <h4>What do I need to know before I use this?</h4>
<p>             If you are not familiar with the AWS CLI or tokens this page is probably not useful to you (yet) and you should <a href="http://aws.amazon.com/cli/">start at AWS cli tools documentation</a> and <a href="http://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html">Amazon's STS documentation</a>.
</p> 

          <h4>Who is this for?</h4>
          <p>If you are writing scripts or have manual interaction with AWS cli but do not want to store long-term credentials in files or environment variables, this tool will probably be helpful to you.</p>

<!--
          <h4>How can I use this?</h4>
<p>The easiest way to use it is to copy paste the values as bash environment variables and start running aws cli commands. If you have not used the aws command line tools or the aws apis for scripting you need to <a href="http://aws.amazon.com/cli/">start there</a>. </p>

          <h4>Why use this?</h4>
AWS federation allows login in to AWS console by authenticating against enterprise accounts (e.g.Active Directory) rather than provisioning users in AWS. <br/>Some people would like extend that federation model to make Command Line and API calls. <br/>Instead of using long-term access keys (and worrying about their safety), the user can make calls using the temporary credentials above. Using this extended form of federation an organization can reduce the number of credentials provisioned inside AWS and instead manage authentication on its own (e.g. exclusively inside Active Directory, without ever provisioning passwords or keys to users inside AWS.)</p>
-->
	</div>

        <div class="col-lg-6">
          <h3>Usage Guide</h3>
          <h4>Demo video</h4>
          <p>You can watch this <a href="https://www.youtube.com/watch?v=sO04BEZSwZA">quick demo video </a>. </p>

          <h4>Getting a token</h4>
	  <p>Simply go to your company's single sign on page (previously provided to you. It looks something like https://adfs.mycompany.com/sign-in) and select "Amazon Web Services - STS" as the target website to log into (<a href="https://www.youtube.com/watch?v=sO04BEZSwZA">as seen in the quick demo video</a>)</p>

          <h4>Using the token with bash</h4>
          <p>Make sure you have set your aws region. All other variables (e.g. secret key) will be provided by the token:</p>
          <pre class="code">$ export AWS_DEFAULT_REGION=us-west-2
$ # just copy/paste token here</pre>

<p>Notice that the output you are pasting are simply environment variables.</p>

          <h4>How long is the token valid?</h4>
          <p>60 minutes.</p>

          <h4>Can the Token last longer?</h4>
          <p>No. This is a hard limit set by amazon. Good news is you don't need to re-type your credentials. As long as you are logged in you can just refresh this page and get a new token.</p>

          <h4>Can I just save the token and use it later?</h4>
          <p>No. STS tokens need to be redeemed within 5 minutes of issuance. Again, this is a hard limit set by Amazon.</p>
          <h4>Can I use this beyond scripts?</h4>
          <p>Not recommended. For longer term authentication there are other options, such as giving your EC2 instance a role. This service is intended as support for running scripts or making manual calls. </p>

        </div>
<div>
          <h4>Using the token with MS Windows/other shells</h4>
          <p>The syntax for environment variables is different in windows, so you have a couple of options:</p> 
<ul>
 <li>Use a bash terminal under windows. <a href="http://www.cygwin.com/">Cygwin</a>, <a href="http://www.mingw.org/wiki/MSYS">mingw</a> and others are freely available.</li>
 <li>Use sh under powershell. The simplest way to get this cmdlet it is by installing it blundled with <a href="https://desktop.github.com">git</a>. Invoke sh from powershell and follow the same instructions as above for bash</li>
 <li>If you do not want to use any of the options above, you can process the JSON or bash outputs with your favorite tool. For example, the following takes the bash input you copy/paste from this page, parses it, and exports the values <b>using only Powershell</b>:</li>
</ul>
          <pre class="code-windows">
Read-Host | %{ $variable = $_.Split('=')[0].Split(' ')[1]; $value = $_.Split('=')[1].Split(';')[0]; [Environment]::SetEnvironmentVariable($variable,($value -replace'"',''),"Process");}
</pre>
<p>Naturally you can copy/paste the above or save it as a helper script and reuse it:

          <pre class="code-windows">
PS C:\Users\you> convert.ps1
# now paste the bash output, the environment variables are added:
PS C:\Users\you> Get-ChildItem Env:

Name                           Value
----                           -----
APPDATA                        C:\Users\you\AppData\Roaming
AWS_ACCESS_KEY_ID              ASIAJLFSY6QKXWRDEMUQ
AWS_SECRET_ACCESS_KEY          XyPidzd6sPj3aVYVGb8yScMp5tgCscoP8rUuhvQW
AWS_SECURITY_TOKEN             AQoDYXdzEID//////////wEa0AJoJoBbtLUMoUw+eDay24splKzuR9MPt1iU/LkKrrzguwA6ffD0mKcsFgU38...
CommonProgramFiles             C:\Program Files\Common Files
...
</pre>


<h4>Reusing the code outside of the web interface</h4>
<p>The code for this app (parsing the SAML response, generating STS) can be reused independently of the web interface. See <a href="https://github.com/fabioarciniegas/STS_dispenser/blob/master/sts_dispenser_cli.php">sts_dispenser_cli in github</a>  for details.</p>

</div>
      </div>
      <footer class="footer">
        <p class="copyright">&copy; 2015</p>
      </footer>
    </div>
 <!-- SCRAPEABLE

<?php echo $all_tokens_one_bash?>
total_sts_tokens = <?php echo $token_acquired?>;

 -->


  </body>
</html>
