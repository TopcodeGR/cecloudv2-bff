package com.ptopalidis.cecloud.bff.properties;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Map;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class NotAConfiguredOpenidProviderException extends RuntimeException {
    private static final long serialVersionUID = 5189849969622154264L;

    public NotAConfiguredOpenidProviderException(Map<String, Object> claims) {
        super(
                "Could not resolve OpenID Provider configuration properties from a JWT with %s as issuer and %s as audience"
                        .formatted(claims.get("iss"), claims.get("aud")));
    }

}
