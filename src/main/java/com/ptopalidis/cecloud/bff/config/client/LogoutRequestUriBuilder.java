package com.ptopalidis.cecloud.bff.config.client;

import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.net.URI;
import java.util.Optional;

public interface LogoutRequestUriBuilder {

    Optional<String> getLogoutRequestUri(ClientRegistration clientRegistration, String idToken);

    Optional<String> getLogoutRequestUri(ClientRegistration clientRegistration, String idToken, Optional<URI> postLogoutUri);
}