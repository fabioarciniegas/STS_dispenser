# STS_dispenser

A SAML 2.0 Service Provider, which serves AWS STS tokens. In other words is a helper app that gives you temporary credentials to make AWS calls. The STS is the result of authenticating with your enterprise credentials instead of using AWS long-term credentials associated with a user.

## Why?

AWS federation is commonly understood as loggin in to AWS console by authenticating through Active Directory. Some people would like extend that federation model to additionally make CLI and API calls. Instead of using long-term access keys, the user can make calls using temporary credentials. Using this extended form of federation an organization can reduce the number of credentials provisioned inside AWS and instead manage authentication on its own (e.g. exclusively inside Active Directory, without ever provisioning passwords or keys to users inside AWS.)


# Installation

Install composer if you have not done so already:

```
curl -sS https://getcomposer.org/installer | php
```

install ext-curl and php SimpleXML(enabled by default in php5) if you haven't. Typically achieved through your favorite package manager. e.g.
```
sudo apt-get install php5-curl
```

install dependency libraries (aws libraries etc. specified in composer.json)
```
php composer.phar install
```

Make www directory available through webserver. e.g. point the document root of your virtual server in apache 2

```
 DocumentRoot /var/webapps/STS_dispenser/www
```

TODO: explain configuration of IdP.


## Local Dependencies 
 
 - a webserver running php5
 - aws libraries for php 2.*

## Federation Dependencies

This application acts as a SAML 2.0 Service Provider. For it to work,  it needs a SAML 2.0 Identity Provider. 


=Fabio Arciniegas, Trend Micro 2015
 