package com.ptopalidis.cecloud.bff.filter;



import com.ptopalidis.cecloud.bff.domain.CECloudSession;
import com.ptopalidis.cecloud.bff.domain.KeycloakTokenIntrospectionResponse;
import com.ptopalidis.cecloud.bff.domain.KeycloakTokenResponse;
import com.ptopalidis.cecloud.bff.service.AuthenticationService;
import com.ptopalidis.cecloud.bff.service.CECloudSessionService;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;


import java.io.IOException;
import java.util.*;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {


    private Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);
    private final AuthenticationService authenticationService;
    private final CECloudSessionService sessionService;


    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return !path.contains("/api");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

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

        if (sessionCookie.isEmpty()) {
            authenticationService.handleUnauthenticatedResponse(response);
            return;
        }

        Optional<CECloudSession> session = sessionService.getSessionBySessionId(sessionCookie.get().getValue());

        if (session.isEmpty()) {
            authenticationService.handleUnauthenticatedResponse(response);
            return;
        }

        KeycloakTokenIntrospectionResponse keycloakTokenIntrospectionResponse = authenticationService.introspectToken(session.get());

        if (!keycloakTokenIntrospectionResponse.getActive()) {
            try{
                CECloudSession newSession = authenticationService.authenticateWithRefreshToken(session.get().getRefreshToken());
                authenticationService.handleAuthenticatedResponse(response, newSession);
                AddUserIdHeaderWrapper mutatedRequest = new AddUserIdHeaderWrapper(request);
                mutatedRequest.putHeader("x-user-id", newSession.getUserId());
                chain.doFilter(mutatedRequest, response);
            } catch (ResponseStatusException ex) {
                authenticationService.logoutLocal(session.get());
                authenticationService.logoutKeycloak(session.get());
                authenticationService.handleUnauthenticatedResponse(response);
                return;
            }
        }
        AddUserIdHeaderWrapper mutatedRequest = new AddUserIdHeaderWrapper(request);
        mutatedRequest.putHeader("x-user-id", session.get().getUserId());
        chain.doFilter(mutatedRequest, response);
    }

    private static class AddUserIdHeaderWrapper extends HttpServletRequestWrapper {
        private final Map<String, String> customHeaders;

        public AddUserIdHeaderWrapper(HttpServletRequest request) {
            super(request);
            this.customHeaders = new HashMap<String, String>();
        }

        public void putHeader(String name, String value){
            this.customHeaders.put(name, value);
        }

        public String getHeader(String name) {

            String headerValue = customHeaders.get(name);

            if (headerValue != null){
                return headerValue;
            }

            return ((HttpServletRequest) getRequest()).getHeader(name);
        }


        public Enumeration<String> getHeaderNames() {

            Set<String> set = new HashSet<>(customHeaders.keySet());

            Enumeration<String> e = ((HttpServletRequest) getRequest()).getHeaderNames();
            while (e.hasMoreElements()) {
                String n = e.nextElement();
                set.add(n);
            }

            return Collections.enumeration(set);
        }


        public Enumeration<String> getHeaders(String name) {
            if ("x-user-id".equalsIgnoreCase(name)) {
                return Collections.enumeration(Collections.singleton(customHeaders.get("x-user-id")));
            }
            return super.getHeaders(name);
        }
    }
}