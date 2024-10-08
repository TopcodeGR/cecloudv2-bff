package com.ptopalidis.cecloud.bff.config.client;

import com.ptopalidis.cecloud.bff.properties.OidcClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Optional;
import java.util.regex.Pattern;


@Component
public class OAuth2AuthorizationRequestResolver  implements ServerOAuth2AuthorizationRequestResolver {

    private static final Pattern authorizationRequestPattern = Pattern.compile("\\/oauth2\\/authorization\\/([^\\/]+)");

    private final URI clientUri;
    private final ServerWebExchangeMatcher authorizationRequestMatcher;
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;
    
    public OAuth2AuthorizationRequestResolver(
            OAuth2ClientProperties bootClientProperties,
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            OidcClientProperties oidcClientProperties) {
        this.clientUri = oidcClientProperties.getClientUri();
        this.authorizationRequestMatcher =
                new PathPatternParserServerWebExchangeMatcher(DefaultServerOAuth2AuthorizationRequestResolver.DEFAULT_AUTHORIZATION_REQUEST_PATTERN);


        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
        return this.authorizationRequestMatcher
                .matches(exchange)
                .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
                .map(ServerWebExchangeMatcher.MatchResult::getVariables)
                .map((variables) -> variables.get(DefaultServerOAuth2AuthorizationRequestResolver.DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME))
                .cast(String.class)
                .flatMap((clientRegistrationId) -> resolve(exchange, clientRegistrationId));
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId) {
        final var delegate = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        return savePostLoginUrisInSession(exchange).then(delegate.resolve(exchange, clientRegistrationId).map(this::postProcess));
    }

    private Mono<WebSession> savePostLoginUrisInSession(ServerWebExchange exchange) {
        final var request = exchange.getRequest();
        final var headers = request.getHeaders();
        final var params = request.getQueryParams();
        return exchange.getSession().map(session -> {
            Optional.ofNullable(
                            Optional.ofNullable(headers.getFirst(OidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
                                    .orElse(Optional.ofNullable(params.getFirst(OidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM)).orElse(null)))
                    .filter(StringUtils::hasText).map(URI::create).ifPresent(postLoginSuccessUri -> {
                        session.getAttributes().put(OidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, postLoginSuccessUri);
                    });

            Optional.ofNullable(
                            Optional.ofNullable(headers.getFirst(OidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER))
                                    .orElse(Optional.ofNullable(params.getFirst(OidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM)).orElse(null)))
                    .filter(StringUtils::hasText).map(URI::create).ifPresent(postLoginFailureUri -> {
                        session.getAttributes().put(OidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, postLoginFailureUri);
                    });

            return session;
        });
    }


    private OAuth2AuthorizationRequest postProcess(OAuth2AuthorizationRequest request) {
        final var modified = OAuth2AuthorizationRequest.from(request);

        final var original = URI.create(request.getRedirectUri());
        final var redirectUri =
                UriComponentsBuilder.fromUri(clientUri).path(original.getPath()).query(original.getQuery()).fragment(original.getFragment()).build().toString();
        modified.redirectUri(redirectUri);

        return modified.build();
    }

}
