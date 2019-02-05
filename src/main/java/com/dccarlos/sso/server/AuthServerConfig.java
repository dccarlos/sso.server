package com.dccarlos.sso.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer
                .tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
                .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')")
                .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .pathMapping("/oauth/authorize", "/v1/authorize")
                .pathMapping("/oauth/token", "/v1/token")
                .pathMapping("/oauth/revoke", "/v1/revoke")
                .pathMapping("/oauth/logout", "/v1/logout")
                .pathMapping("/oauth/check_token", "/v1/check_token")
                .pathMapping("/oauth/confirm_access", "/v1/confirm_access")
                .pathMapping("/oauth/error", "/v1/error");
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("app01-client-id")
                .secret(passwordEncoder.encode("app01-client-secret"))
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .scopes("openid", "profile", "email")
                .autoApprove(true)
                .redirectUris("http://localhost:8080", "http://localhost:8080/api/auth/callback", "http://localhost:8082/ui/login", "http://localhost:8083/ui2/login", "http://localhost:8082/login");
    }
}