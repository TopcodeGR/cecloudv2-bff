package com.ptopalidis.cecloud.bff.config.client;

import com.ptopalidis.cecloud.bff.properties.OidcClientProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@RequiredArgsConstructor
public class OAuth2ServerRedirectStrategy implements ServerRedirectStrategy {
    private final HttpStatus defaultStatus;

    @Override
    public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location) {
        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            final var status = Optional
                    .ofNullable(exchange.getRequest().getHeaders().get(OidcClientProperties.RESPONSE_STATUS_HEADER))
                    .map(List::stream)
                    .orElse(Stream.empty())
                    .filter(StringUtils::hasLength)
                    .findAny()
                    .map(statusStr -> {
                        try {
                            final var statusCode = Integer.parseInt(statusStr);
                            return HttpStatus.valueOf(statusCode);
                        } catch (NumberFormatException e) {
                            return HttpStatus.valueOf(statusStr.toUpperCase());
                        }
                    })
                    .orElse(defaultStatus);
            response.setStatusCode(status);

            response.getHeaders().setLocation(location);
        });
    }
}
