<?php 
require("../../config.php"); 
?>
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="<?php echo SP_ID?>">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="<?php echo SP_ID?>" index="0"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" Location="<?php echo SP_ID?>" index="1"/>
  </md:SPSSODescriptor>
  <md:ContactPerson contactType="technical">
    <md:GivenName><?php echo CONTACT_PERSON_NAME?></md:GivenName>
    <md:EmailAddress><?php echo CONTACT_PERSON_ADDRESS?></md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>
