# STS_dispenser

A SAML 2.0 Service Provider, which serves AWS STS tokens. In other words is a helper app that gives you temporary credentials to make AWS calls. The STS is the result of authenticating with your enterprise credentials instead of using AWS long-term credentials associated with a user.

## Why?

AWS federation is commonly understood as loggin in to AWS console by authenticating through Active Directory. Some people would like extend that federation model to additionally make CLI and API calls. Instead of using long-term access keys, the user can make calls using temporary credentials. Using this extended form of federation an organization can reduce the number of credentials provisioned inside AWS and instead manage authentication on its own (e.g. exclusively inside Active Directory, without ever provisioning passwords or keys to users inside AWS.)


Fabio Arciniegas, Trend Micro 2015
