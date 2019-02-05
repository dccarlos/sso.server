# Basic Oauth2 Auth Server
_Since most of the projects I'm involved in use OAuth2's authorization-code-flow I created this basic project to work on
my local without using an external service (like OKTA developer console)_

## Instructions

#### Set in your **client** code:
1. ```clientId: app01-client-id```
2. ```clientSecret: app01-client-secret```
3. ```accessTokenUri: http://localhost:8081/oauth2/v1/token```
4. ```userAuthorizationUri: http://localhost:8081/oauth2/v1/authorize```
5. ```userInfoUri: http://localhost:8081/oauth2/user/me```

#### For HA folks
```yaml
  clientSecret: app01-client-secret
    baseUrl: http://localhost:8081/
    authorizationPath: oauth2/v1/authorize
    revokeTokenPath: oauth2/v1/revoke
    logoutTokenPath: oauth2/v1/logout
    accessTokenPath: oauth2/v1/token
    scopes: openid profile email
    
    redirectPath: api/auth/callback # <= This is on the client side
```

#### Run Auth Server
```
git clone git@github.com:dccarlos/sso.server.git
cd sso.server
mvn spring-boot:run
```

#### Credentials
```
Username: carlos
Password: 123
```
      
      
      
      