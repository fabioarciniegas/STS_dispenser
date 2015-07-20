<?php
# Read the configuration from the idp and make it available through
# the config array to the rest of the application.  

$xml = simplexml_load_file($config['IdentityProviderMetadata']) or print('Fatal Error: config file pointing to broken idp metadata');
$md_ns = $xml->children('urn:oasis:names:tc:SAML:2.0:metadata');
$location = $md_ns->IDPSSODescriptor->SingleSignOnService->attributes()->Location;
$config['IdPSingleSignOnURL'] =  $location;

function generateAuthnRequest() {
# Note that this "unique id" does not need to be cryptographically
# strong for the purposes of the request.  The purpose of this id is
# to match that an eventual assertion posted to this SP is in
# response to a request initiated from the SP. Note that since the
# post can be originated by the iDP without a request from the SP AND the
# authenticity of the assertion is verified using the certificate of
# the iDP and NOT this unique id,  there is no need to create a
# cryptographically strong value. In fact, given TLS between SP and
# IDP and correct verification of the signature in the assertion, this
# id can be ignored altogether for the purposes of this SP. 


$authnRequestTemplate = <<<AUTHREQ
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%1"
    Version="2.0"
    AssertionConsumerServiceIndex="0"
    AttributeConsumingServiceIndex="0">
    <saml:Issuer>URN:xx-xx-xx</saml:Issuer>
    <samlp:NameIDPolicy
        AllowCreate="true"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
</samlp:AuthnRequest>
AUTHREQ;

    $saml = sprintf($authnRequestTemplate,uniqid());
    $utf8 = utf8_encode($saml);
    $base64 = base64_encode($utf8);
   return $base64;
}


?>