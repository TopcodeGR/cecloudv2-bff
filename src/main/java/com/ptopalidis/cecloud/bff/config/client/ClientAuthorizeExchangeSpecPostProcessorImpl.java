package com.ptopalidis.cecloud.bff.config.client;

import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.stereotype.Component;

@Component
public class ClientAuthorizeExchangeSpecPostProcessorImpl implements  ClientAuthorizeExchangeSpecPostProcessor{

    @Override
    public ServerHttpSecurity.AuthorizeExchangeSpec authorizeHttpRequests(ServerHttpSecurity.AuthorizeExchangeSpec spec) {
        return spec.anyExchange().authenticated();
    }
}
