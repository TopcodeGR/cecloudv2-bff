package com.ptopalidis.cecloud.bff.config.client;

import com.ptopalidis.cecloud.bff.properties.OidcClientProperties;
import com.ptopalidis.cecloud.bff.properties.OidcProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;


@Component
public class OAuth2ServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {
    private final URI defaultRedirectUri;
    private final OAuth2ServerRedirectStrategy redirectStrategy;

    public OAuth2ServerAuthenticationSuccessHandler(OidcProperties oidcProperties) {
        this.defaultRedirectUri = URI.create("/");
        this.redirectStrategy = new OAuth2ServerRedirectStrategy(oidcProperties.getClient().getOauth2Redirections().getPostAuthorizationCode());
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        return webFilterExchange.getExchange().getSession().flatMap(session -> {
            final var uri =
                    session.getAttributeOrDefault(OidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, defaultRedirectUri);
            return redirectStrategy.sendRedirect(webFilterExchange.getExchange(), uri);
        });
    }

}
