package com.ptopalidis.cecloud.bff.config.client;

import com.ptopalidis.cecloud.bff.properties.OidcClientProperties;
import com.ptopalidis.cecloud.bff.properties.OidcProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Optional;

@Component
public class OidcServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {
    private final LogoutRequestUriBuilder uriBuilder;
    private final ReactiveClientRegistrationRepository clientRegistrationRepo;
    private final ServerRedirectStrategy redirectStrategy;
    private final String defaultPostLogoutUri;


    public OidcServerLogoutSuccessHandler(
            LogoutRequestUriBuilder uriBuilder,
            ReactiveClientRegistrationRepository clientRegistrationRepo,
            OidcProperties oidcProperties) {
        this.defaultPostLogoutUri = null;
        this.uriBuilder = uriBuilder;
        this.clientRegistrationRepo = clientRegistrationRepo;
        this.redirectStrategy = new OAuth2ServerRedirectStrategy(oidcProperties.getClient().getOauth2Redirections().getRpInitiatedLogout());
    }

    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauth) {
            final var postLogoutUri = Optional
                    .ofNullable(exchange.getExchange().getRequest().getHeaders().getFirst(OidcClientProperties.POST_LOGOUT_SUCCESS_URI_HEADER))
                    .orElse(
                            Optional
                                    .ofNullable(
                                            exchange.getExchange().getRequest().getQueryParams().getFirst(OidcClientProperties.POST_LOGOUT_SUCCESS_URI_PARAM))
                                    .orElse(defaultPostLogoutUri));

            return clientRegistrationRepo.findByRegistrationId(oauth.getAuthorizedClientRegistrationId()).flatMap(client -> {
                if (StringUtils.hasText(postLogoutUri)) {
                    return Mono
                            .justOrEmpty(
                                    uriBuilder
                                            .getLogoutRequestUri(
                                                    client,
                                                    ((OidcUser) oauth.getPrincipal()).getIdToken().getTokenValue(),
                                                    Optional.of(URI.create(postLogoutUri))));
                }
                return Mono.justOrEmpty(uriBuilder.getLogoutRequestUri(client, ((OidcUser) oauth.getPrincipal()).getIdToken().getTokenValue()));
            }).flatMap(logoutUri -> this.redirectStrategy.sendRedirect(exchange.getExchange(), URI.create(logoutUri)));
        }
        return Mono.empty().then();
    }
}
