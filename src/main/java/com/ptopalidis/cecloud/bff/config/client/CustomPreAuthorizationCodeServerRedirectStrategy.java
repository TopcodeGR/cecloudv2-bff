package com.ptopalidis.cecloud.bff.config.client;

import org.springframework.http.HttpStatus;

public class CustomPreAuthorizationCodeServerRedirectStrategy extends OAuth2ServerRedirectStrategy implements PreAuthorizationCodeServerRedirectStrategy {
    public CustomPreAuthorizationCodeServerRedirectStrategy(HttpStatus defaultStatus) {
        super(defaultStatus);
    }
}