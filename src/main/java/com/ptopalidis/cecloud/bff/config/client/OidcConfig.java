package com.ptopalidis.cecloud.bff.config.client;

import com.ptopalidis.cecloud.bff.properties.CorsProperties;
import com.ptopalidis.cecloud.bff.properties.OidcProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Optional;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class OidcConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         OidcProperties oidcProperties,
                                                         ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
                                                         PreAuthorizationCodeServerRedirectStrategy preAuthorizationCodeRedirectStrategy,
                                                         Optional<ServerAuthenticationSuccessHandler> authenticationSuccessHandler,
                                                         Optional<ServerAuthenticationFailureHandler> authenticationFailureHandler,
                                                         Optional<ServerLogoutHandler> logoutHandler,
                                                         ServerLogoutSuccessHandler logoutSuccessHandler,
                                                         ServerProperties serverProperties,
                                                         ClientAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
                                                         ClientReactiveHttpSecurityPostProcessor httpPostProcessor) {



        final var clientRoutes = oidcProperties
                .getClient()
                .getSecurityMatchers()
                .stream()
                .map(PathPatternParserServerWebExchangeMatcher::new)
                .map(ServerWebExchangeMatcher.class::cast)
                .toList();
        http.securityMatcher(new OrServerWebExchangeMatcher(clientRoutes));
        http.oauth2Login(oauth2 -> {
            oauth2.authorizationRequestResolver(authorizationRequestResolver);
            oauth2.authorizationRedirectStrategy(preAuthorizationCodeRedirectStrategy);
            authenticationSuccessHandler.ifPresent(oauth2::authenticationSuccessHandler);
            authenticationFailureHandler.ifPresent(oauth2::authenticationFailureHandler);
        });
        http.logout((logout) -> {
            logoutHandler.ifPresent(logout::logoutHandler);
            logout.logoutSuccessHandler(logoutSuccessHandler);
        });
        final var corsProps = new ArrayList<>(oidcProperties.getCors());
        final var permittedCorsOptions = corsProps
                .stream()
                .filter(cors -> (cors.getAllowedMethods().contains("*") || cors.getAllowedMethods().contains("OPTIONS")) && !cors.isDisableAnonymousOptions())
                .map(CorsProperties::getPath)
                .toList();

        if (!oidcProperties.getClient().getPermitAll().isEmpty() || !permittedCorsOptions.isEmpty()) {
            http.anonymous(withDefaults());
        }

        if (!oidcProperties.getClient().getPermitAll().isEmpty()) {
            http.authorizeExchange(authorizeExchange -> authorizeExchange.pathMatchers(oidcProperties.getClient().getPermitAll().toArray(new String[] {})).permitAll());
        }

        if (!permittedCorsOptions.isEmpty()) {
            http
                    .authorizeExchange(
                            authorizeExchange -> authorizeExchange.pathMatchers(HttpMethod.OPTIONS, permittedCorsOptions.toArray(new String[] {})).permitAll());
        }

        http.anonymous(withDefaults());

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.redirectToHttps(withDefaults());
        }

        http.csrf(csrfSpec -> csrfSpec.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()));
        http.authorizeExchange(authorizePostProcessor::authorizeHttpRequests);
        httpPostProcessor.process(http);



        return http.build();
    }


    CorsWebFilter corsFilter(OidcProperties oidcProperties) {
        final var corsProperties = new ArrayList<>(oidcProperties.getCors());
        final var source = new UrlBasedCorsConfigurationSource();
        for (final var corsProps : corsProperties) {
            final var configuration = new CorsConfiguration();
            configuration.setAllowCredentials(corsProps.getAllowCredentials());
            configuration.setAllowedHeaders(corsProps.getAllowedHeaders());
            configuration.setAllowedMethods(corsProps.getAllowedMethods());
            configuration.setAllowedOriginPatterns(corsProps.getAllowedOriginPatterns());
            configuration.setExposedHeaders(corsProps.getExposedHeaders());
            configuration.setMaxAge(corsProps.getMaxAge());
            source.registerCorsConfiguration(corsProps.getPath(), configuration);
        }
        return new CorsWebFilter(source);
    }

    @Bean
    WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {

            Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
            return csrfToken.doOnSuccess(token -> {

            }).then(chain.filter(exchange));
        };
    }


    @Bean
    PreAuthorizationCodeServerRedirectStrategy preAuthorizationCodeRedirectStrategy(OidcProperties oidcProperties) {
        return new CustomPreAuthorizationCodeServerRedirectStrategy(
                oidcProperties.getClient().getOauth2Redirections().getPreAuthorizationCode());
    }

}
