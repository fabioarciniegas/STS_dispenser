<?php
require '/home/ubuntu/vendor/autoload.php';
use Aws\Sts\StsClient;
use Aws\Iam\IamClient;

try {

$client = StsClient::factory(array(
    'region' => 'us-east-2',
    'version' => 'latest')
);

$method = $_SERVER['REQUEST_METHOD'];

if ($method != "POST") {
   print "This is not a page to be called directly.  <a href=\"https://ec2-52-4-120-194.compute-1.amazonaws.com/saml/module.php/saml/disco.php?entityID=https%3A%2F%2Fec2-52-4-120-194.compute-1.amazonaws.com%2Fsaml%2Fmodule.php%2Fsaml%2Fsp%2Fmetadata.php%2FSTSDispenser-SP&return=https%3A%2F%2Fec2-52-4-120-194.compute-1.amazonaws.com%2Fsaml%2Fmodule.php%2Fsaml%2Fsp%2Fdiscoresp.php%3FAuthID%3D_e6c6daf549e961f61680f96a8d604e308124f4df4a%253Ahttps%253A%252F%252Fec2-52-4-120-194.compute-1.amazonaws.com%252Fsaml%252Fmodule.php%252Fcore%252Fas_login.php%253FAuthId%253DSTSDispenser-SP%2526ReturnTo%253Dhttps%25253A%25252F%25252Fec2-52-4-120-194.compute-1.amazonaws.com%25252Fsaml%25252Fmodule.php%25252Fcore%25252Fauthenticate.php%25253Fas%25253DSTSDispenser-SP&returnIDParam=idpentityid\">Start at your Identity Provider.</a>";
   exit();
}

//print base64_decode($_POST['SAMLResponse']);
//$input = print file_get_contents("php://input");

$result = $client->assumeRoleWithSAML(array(
    // RoleArn is required
    'RoleArn' => 'arn:aws:iam::556247969450:role/STSasIdPAssume',
    // PrincipalArn is required
    'PrincipalArn' => 'arn:aws:iam::556247969450:saml-provider/STSTokenProvierAsIdP',
    // SAMLAssertion is required
    'SAMLAssertion' => $_POST['SAMLResponse'],
//    'Policy' => 'string',
    'DurationSeconds' => 3600,
));

$exp = $result['Credentials']['Expiration'];
$exp2 = strtotime($exp);
$current_time = time();
$diff = round(($exp2 - $current_time)/60,2);

print "<title>Your STS Token</title>";
print "You now have an AWS Security Token. These are temporary credentials you can use instead of hard-coding your actual secret key/access key.</b><br/>";
print "<br/>To use them, configure the following as your AWS credentials the way you normally would (e.g. for cli scripts, copy paste the following to a linux terminal):<br/><br/>";

print "<textarea rows=4 cols=120>";
print "export AWS_ACCESS_KEY_ID=" . $result['Credentials']['AccessKeyId'] . "\n";
print "export AWS_SECRET_ACCESS_KEY=" . $result['Credentials']['SecretAccessKey'] . "\n";
print "export AWS_SECURITY_TOKEN=" . $result['Credentials']['SessionToken'] . "\n";
print "</textarea>";

print "<br/>This token is valid until " . $result['Credentials']['Expiration'] . "(". $diff ." minutes)";

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

} catch (Exception $e) {

//print $e;
   print "<br/><br/>If you have trouble reloading this page.  <a href=\"https://ec2-52-4-120-194.compute-1.amazonaws.com/saml/module.php/saml/disco.php?entityID=https%3A%2F%2Fec2-52-4-120-194.compute-1.amazonaws.com%2Fsaml%2Fmodule.php%2Fsaml%2Fsp%2Fmetadata.php%2FSTSDispenser-SP&return=https%3A%2F%2Fec2-52-4-120-194.compute-1.amazonaws.com%2Fsaml%2Fmodule.php%2Fsaml%2Fsp%2Fdiscoresp.php%3FAuthID%3D_e6c6daf549e961f61680f96a8d604e308124f4df4a%253Ahttps%253A%252F%252Fec2-52-4-120-194.compute-1.amazonaws.com%252Fsaml%252Fmodule.php%252Fcore%252Fas_login.php%253FAuthId%253DSTSDispenser-SP%2526ReturnTo%253Dhttps%25253A%25252F%25252Fec2-52-4-120-194.compute-1.amazonaws.com%25252Fsaml%25252Fmodule.php%25252Fcore%25252Fauthenticate.php%25253Fas%25253DSTSDispenser-SP&returnIDParam=idpentityid\">Start at your Identity Provider.</a>";
   exit();

  
}

// header('Content-Type: ' . $response->get('ContentType'));

// 		      echo $response->get('Body');
?>