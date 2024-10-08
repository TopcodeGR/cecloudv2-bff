package com.ptopalidis.cecloud.bff.config.client;

import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.stereotype.Component;

@Component
public class ClientReactiveHttpSecurityPostProcessorImpl implements  ClientReactiveHttpSecurityPostProcessor{
    @Override
    public ServerHttpSecurity process(ServerHttpSecurity serverHttpSecurity) {
        return serverHttpSecurity;
    }
}
