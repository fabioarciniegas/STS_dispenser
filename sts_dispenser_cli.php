<?php

require("config.php"); 
require 'vendor/autoload.php';

use Aws\Sts\StsClient;
use Aws\Iam\IamClient;

# This is a helper script that allows a local parsing of a saml assertion
# rather than going through the web interface of STS dispenser. The logic
# is the same. However, the assertion is taken from a file rather than from
# a POST parameter.

# It is formatted as a php script rather than perl to keep
# dependencies consistent between web interface and cli. 
#
# Fabio Arciniegas 2015

$all_tokens_one_bash = "";
$token_acquired = "";


try {
    $client = StsClient::factory(array(
             'region' => STS_CLIENT_REGION,
             'version' => 'latest'));

    (count($argv) >1) or die("Required Argument Missing.\nUsage: php {$argv[0]} <saml assertion filename>\n");

    $raw_assertion = file_get_contents($argv[1]);
    $assertion = base64_decode($raw_assertion);
    $assertion_xml = simplexml_load_string($assertion);

    if($assertion_xml === false){
	throw new Exception("Malformed XML for SAML assertion.");
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
                                       'SAMLAssertion' => $raw_assertion,
                                       'DurationSeconds' => 3600));


      #  $iamClient = IamClient::factory([
      #             'credentials' => $client->createCredentials($current_token),
      #             'version' => 'latest']);
      #  $account_alias = $iamClient->listAccountAliases();


      # if(count($account_alias['AccountAliases']) > 0){ 
      #    $short_role = $arn_pieces[2]."_".$account_alias['AccountAliases'][0];
      # }

     $result[$short_role] = $current_token;

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


     $token_acquired++;


    } catch (Exception $e) {
     error_log("No token for ".$pieces[1].".".$e->getMessage());
     }
}

   if ($token_acquired === 0){          
      throw new Exception("An assertion was received but no token from it could be acquired.");
   }

    print $all_tokens_one_bash;
    print "total_tokens={$token_acquired};\n";

} 
catch (Exception $e) {
    error_log($e->getMessage());
}


?>
