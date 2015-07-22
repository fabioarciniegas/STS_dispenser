<?php
# Read the configuration from the idp and make it available through
# the config array to the rest of the application.  

$xml = simplexml_load_file(IDP_METADATA) or print('Fatal Error: config file pointing to broken idp metadata');
$md_ns = $xml->children('urn:oasis:names:tc:SAML:2.0:metadata');

define('IDP_SSO_URL',$md_ns->IDPSSODescriptor->SingleSignOnService->attributes()->Location);
define('IDP_SLO_URL',$md_ns->IDPSSODescriptor->SingleLogoutService->attributes()->Location);

function generateAuthnRequest($prevent_encoding = false) {
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
    IssueInstant="%s"
    ID="%s"
    Version="2.0"
    Destination="%s"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
   AssertionConsumerServiceURL="%s"
    AssertionConsumerServiceIndex="0"
    AttributeConsumingServiceIndex="0">
    <saml:Issuer>%s</saml:Issuer>
    <samlp:NameIDPolicy
        AllowCreate="true"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
</samlp:AuthnRequest>
AUTHREQ;

    $saml = sprintf($authnRequestTemplate,gmdate("Y-m-d\TH:i:s\Z"),
                        uniqid(),
                        SP_ID,
                        SP_ID,
                        SP_ID
) ;
$utf8 = utf8_encode($saml);
$compressed = gzdeflate($utf8,-1,ZLIB_ENCODING_RAW);
$base64 = base64_encode($compressed);
$urlencoded = urlencode($base64);

return $prevent_encoding ? $utf8 : $urlencoded;
}

function decodeSAMLResponse($response) {
	 return base64_decode($response);
}

function after_last ($this, $inthat)
{
   if (!is_bool(strrevpos($inthat, $this)))
   return substr($inthat, strrevpos($inthat, $this)+strlen($this));
}

?>