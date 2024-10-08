package com.ptopalidis.cecloud.bff.config.client;

import com.ptopalidis.cecloud.bff.properties.OidcClientProperties;
import com.ptopalidis.cecloud.bff.properties.OidcProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OAuth2ServerAuthenticationSuccessHandlerTest {

    @Mock
    private OidcProperties oidcProperties;

    @Mock
    private OidcClientProperties oidcClientProperties;

    @Mock
    private WebFilterExchange webFilterExchange;

    @Mock
    private WebSession webSession;

    @Mock
    private Authentication authentication;

    private OAuth2ServerAuthenticationSuccessHandler successHandler;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(oidcProperties.getClient()).thenReturn(oidcClientProperties);
        when(oidcClientProperties.getOauth2Redirections()).thenReturn(new OidcClientProperties.OAuth2RedirectionProperties());
        successHandler = new OAuth2ServerAuthenticationSuccessHandler(oidcProperties);
    }

    @Test
    void onAuthenticationSuccess() {
        when(webFilterExchange.getExchange().getSession()).thenReturn(Mono.just(webSession));
        when(webSession.getAttributeOrDefault(any(), any())).thenReturn(URI.create("/success"));

        Mono<Void> result = successHandler.onAuthenticationSuccess(webFilterExchange, authentication);

        StepVerifier.create(result)
                .verifyComplete();

        verify(webSession).getAttributeOrDefault(OidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, URI.create("/"));
    }
}