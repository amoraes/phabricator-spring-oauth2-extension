# phabricator-spring-oauth2-extension
Phabricator extension to enable oauth2 authorization using a Spring Boot OAuth2 Server

# Installing the extension
- Copy the two files inside the *src* folder to *{Phabricator_install_dir}*/src/extensions
- Edit file PhutilSpringAuthAdapter and change the method getAdapterDomain() to return the domain your auth server is hosted (i.e., auth.yourcompany.com)

# Configuration 
- Create a new client application into your authorization server
- Log in as admin and configure your new authentication provider providing the client id and secret
