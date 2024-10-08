package com.ptopalidis.cecloud.bff.config.client;

import com.ptopalidis.cecloud.bff.properties.OidcClientProperties;
import com.ptopalidis.cecloud.bff.properties.OidcProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;

public class OAuth2ServerAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {

    private final URI defaultRedirectUri;
    private final OAuth2ServerRedirectStrategy redirectStrategy;

    public OAuth2ServerAuthenticationFailureHandler(OidcProperties addonsProperties) {
        this.defaultRedirectUri = URI.create("/");
        this.redirectStrategy = new OAuth2ServerRedirectStrategy(HttpStatus.FOUND);
    }

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
        return webFilterExchange.getExchange().getSession().flatMap(session -> {
            final var uri = UriComponentsBuilder.fromUri(
                            session.getAttributeOrDefault(OidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, defaultRedirectUri))
                    .queryParam(OidcClientProperties.POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, HtmlUtils.htmlEscape(exception.getMessage()))
                    .build().toUri();
            return redirectStrategy.sendRedirect(webFilterExchange.getExchange(), uri);
        });
    }
}
