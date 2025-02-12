package com.ptopalidis.cecloud.bff.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptopalidis.cecloud.bff.domain.CECloudSession;
import com.ptopalidis.cecloud.bff.domain.LoginData;
import com.ptopalidis.cecloud.bff.service.AuthenticationService;
import com.ptopalidis.cecloud.bff.service.CECloudSessionService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.websocket.server.PathParam;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.filter.FormContentFilter;


import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;


@RestController
@RequiredArgsConstructor
public class AuthenticationController {


    private final AuthenticationService authenticationService;
    private final CECloudSessionService sessionService;
    private final ObjectMapper objectMapper;

    @PostMapping("/auth/login")
    public void login(@RequestBody LoginData body, HttpServletResponse response) throws JsonProcessingException {

        try{
            CECloudSession session = authenticationService.login(body);
            authenticationService.handleAuthenticatedResponse(response, session);
        } catch (ResponseStatusException ex) {
            authenticationService.handleUnauthenticatedResponse(response);
        }

    }

    @PostMapping("/auth/logout")
    public void logout(@RequestBody LoginData body, HttpServletRequest request, HttpServletResponse response) throws JsonProcessingException {

        if (ObjectUtils.isEmpty(request.getCookies())){
            authenticationService.handleUnauthenticatedResponse(response);
            return;
        }

        if (request.getCookies().length == 0) {
            authenticationService.handleUnauthenticatedResponse(response);
            return;
        }

        Optional<Cookie> sessionCookie = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(AuthenticationService.SESSION_COOKIE_NAME))
                .findFirst();


        Optional<CECloudSession> session = sessionService.getSessionBySessionId(sessionCookie.get().getValue());

        if (session.isPresent()) {
            authenticationService.logoutLocal(session.get());
            authenticationService.logoutKeycloak(session.get());
        }
        authenticationService.handleUnauthenticatedResponse(response);

    }


    @PostMapping(path = "/auth/logout/back-channel",produces = MediaType.APPLICATION_JSON_VALUE)
    public void logoutBackChannel(@RequestParam("logout_token") String logoutToken) throws JsonProcessingException {

        String logoutTokenDecoded = authenticationService.decodeJwtToken(logoutToken);
        LinkedHashMap<String, Object> logoutTokenParsed = objectMapper.readValue(logoutTokenDecoded, LinkedHashMap.class);

        String keycloakSessionId = logoutTokenParsed.get("sid").toString();
        Optional<CECloudSession> sesssion = sessionService.getSessionByKeycloakSession(keycloakSessionId);

        sesssion.ifPresent(authenticationService::logoutLocal);

    }

}
