package com.ptopalidis.cecloud.bff.config.common;

import org.springframework.security.config.web.server.ServerHttpSecurity;

public interface AuthorizeExchangeSpecPostProcessor {
    ServerHttpSecurity.AuthorizeExchangeSpec authorizeHttpRequests(ServerHttpSecurity.AuthorizeExchangeSpec spec);
}
