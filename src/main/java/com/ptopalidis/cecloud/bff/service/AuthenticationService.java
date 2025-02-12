package com.ptopalidis.cecloud.bff.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptopalidis.cecloud.bff.domain.CECloudSession;
import com.ptopalidis.cecloud.bff.domain.KeycloakTokenIntrospectionResponse;
import com.ptopalidis.cecloud.bff.domain.KeycloakTokenResponse;
import com.ptopalidis.cecloud.bff.domain.LoginData;
import com.ptopalidis.cecloud.bff.repository.SessionRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedCaseInsensitiveMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Service
@RequiredArgsConstructor

public class AuthenticationService {

    private final CECloudSessionService sessionService;
    private final ObjectMapper objectMapper;

    public static final String SESSION_COOKIE_NAME = "CECLOUDSESSION";
    private final SessionRepository sessionRepository;

    @Value( "${spring.security.oauth2.client.registration.keycloak.client-id}" )
    private String clientId;

    @Value( "${spring.security.oauth2.client.registration.keycloak.client-secret}" )
    private String clientSecret;


    public CECloudSession login(LoginData loginData) throws JsonProcessingException {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("username",  loginData.getUsername());
        formData.add("password", loginData.getPassword());
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("scope", "openid");

        return authenticate(formData, true, true);
    }

    public void logoutLocal(CECloudSession session) {
        this.sessionService.deleteSession(session);
    }

    public void logoutKeycloak(CECloudSession session) {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("refresh_token", session.getRefreshToken());
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);

        ResponseEntity<Void> response  = RestClient.create().post()
                .uri("http://localhost:8090/realms/cecloudv2/protocol/openid-connect/logout")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formData)
                .retrieve()
                .onStatus(status-> status.value() != 200  && status.value()!= 204, (req, res) -> {
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized");
                })
                .toBodilessEntity();

    }

    public KeycloakTokenIntrospectionResponse introspectToken(CECloudSession session) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", session.getAccessToken());
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);


        return RestClient.create().post()
                .uri("http://localhost:8090/realms/cecloudv2/protocol/openid-connect/token/introspect")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formData)
                .retrieve()
                .onStatus(status-> status.value() != 200, (req, res) -> {
                    logoutLocal(session);
                    logoutKeycloak(session);
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized");
                })
                .body(KeycloakTokenIntrospectionResponse.class);
    }

    public CECloudSession authenticateWithRefreshToken(String refreshToken) throws JsonProcessingException {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "refresh_token");
        formData.add("refresh_token",  refreshToken);
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);

        return authenticate(formData, true, false);
    }

    public void handleAuthenticatedResponse(HttpServletResponse response, CECloudSession session) {
        Cookie sessionCookie = getSessionCookie(session);
        response.addCookie(sessionCookie);
    }

    public void handleUnauthenticatedResponse(HttpServletResponse response) {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.addCookie(getInvalidatedSessionCookie());
    }



    public String decodeJwtToken(String token) {
        String[] chunks = token.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
       // String header = new String(decoder.decode(chunks[0]));
        return new String(decoder.decode(chunks[1]));
    }


    private CECloudSession authenticate(MultiValueMap<String, String> formData, Boolean logoutLocal, Boolean logoutKeycloak) throws JsonProcessingException {
        KeycloakTokenResponse keycloakTokenResponse =  RestClient.create().post()
                .uri("http://localhost:8090/realms/cecloudv2/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formData)
                .retrieve()
                .onStatus(status-> status.value() != 200, (req, res) -> {
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized");
                })
                .body(KeycloakTokenResponse.class);

        String idToken = decodeJwtToken(keycloakTokenResponse.getIdToken());
        LinkedHashMap<String, Object> idTokenParsed = objectMapper.readValue(idToken, LinkedHashMap.class);
        String userId = idTokenParsed.get("sub").toString();


        Optional<CECloudSession> existingSession  = sessionService.getSessionByUserId(userId);

        if (existingSession.isPresent()) {
            if(logoutLocal) {
                logoutLocal(existingSession.get());
            }

            if(logoutKeycloak){
                logoutKeycloak(existingSession.get());
            }
        }

        return this.sessionService.createSession(CECloudSession
                .builder()
                .sessionId(UUID.randomUUID().toString())
                .accessToken(keycloakTokenResponse.getAccessToken())
                .refreshToken(keycloakTokenResponse.getRefreshToken())
                .idToken(idToken)
                .userId(userId)
                .keycloakSession(keycloakTokenResponse.getKeycloakSession())
                .build());
    }


    private Cookie getSessionCookie(CECloudSession session) {
        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, session.getSessionId());

        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(3600);
        cookie.setAttribute("SameSite", "Strict");

        return cookie;
    }

    private Cookie getInvalidatedSessionCookie() {
        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, null);

        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setAttribute("SameSite", "Strict");

        return cookie;
    }


}
