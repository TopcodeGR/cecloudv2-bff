package com.ptopalidis.cecloud.bff.config.client;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

class SpaCsrfTokenRequestHandler extends ServerCsrfTokenRequestAttributeHandler {
    private final ServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken) {
        this.delegate.handle(exchange, csrfToken);
    }

    @Override
    public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
        return Mono
                .justOrEmpty(exchange.getRequest().getHeaders().getFirst(csrfToken.getHeaderName()))
                .switchIfEmpty(this.delegate.resolveCsrfTokenValue(exchange, csrfToken));
    }
}