<?php

 # Fundamental point of configuration. 
#  You need to get this from your idp. 
define('IDP_METADATA','../idp_metadata.xml');

# If set to true, no saml request included on link to provider
define('IDP_INITIATED_ONLY',true);

# ID of this Service Provider. Usually the location of index.php 
define('SP_ID','https://sts.yourdeploymenturl.com/');


# If user calls this page directly, should he be automatically
# redirected to the IdP sign-in page?  Default is true.
define('AUTO_INITIATE', false);

# If user calls this page directly, should he see a link to the IdP?
define('SHOW_INITIATION_LINK_ON_GET', false);

define('SHOW_INITIATION_LINK_ON_ERROR', true);


# If user calls this page directly, should he be automatically
# redirected to the IdP sign-in page? Default is true.
#define('AutoInitiateOnFail',true);
define('REDIRECT_DELAY',2);

# Forced link on error. Used in case of error if IDP_INITIATED_ONLY is true.
# it provides a way for the user to restart the process from the idp.
# this should not be necessary in most cases. Only if ADFS is not
# configured to support SP-initiated sign-on   
define('STATIC_IDP_INITIATION_URL', 'https://adfs.yourcompany.com/adfs/ls/IdpInitiatedSignon.aspx');

# Show a button allowing for explicit logout
define('PRESENT_LOGOUT',false);

# region to make the STS Client call in
define('STS_CLIENT_REGION','us-east-2');

# Use for debug purposes only. Makes the response from the iDP
# available as base64 in a javascript variable named IdP_assertion,
# which you can inspect from your browser
define('DEBUG_SAML',false);

# For debugging purposes only. Read an xml file with the SAML response, ignore values from POST. 
define('READ_RESPONSE_FILE_INSTEAD',false);
define('RESPONSE_FILE','/var/www/STS_dispenser/static.saml');

# Show a link to the provider on get
define('ShowProviderLinkOnGET',true);

# A friendly name to use.
define('IDP_DISPLAY_NAME','your identity provider');

# The following values are used in the outgoing metadata for this SP

# The public URL of the site. Notice how this is kept manual as a safe way to allow for 
# exactly the right endpoints (e.g. if the sp is load balanced this should be the 
# address of the load balancer, not the instance) 
define('PUBLIC_URL','must configure this variable to the public url of this site');

define('CONTACT_PERSON_NAME','someone');
define('CONTACT_PERSON_ADDRESS', 'someone@internal.com');



# Note: CONFIG ALSO AVAILABLE BUT DEFINED ONLY AFTER PARSING idp_config.php:

# IDP_SSO_URL   : Single Sign On url target for http redirection
# IDP_SLO_URL   : Single Logout out url target for http redirection
?>