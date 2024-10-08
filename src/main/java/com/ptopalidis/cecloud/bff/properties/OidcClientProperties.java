package com.ptopalidis.cecloud.bff.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Data
@ConfigurationProperties("oidc.client")
public class OidcClientProperties {
    public static final String RESPONSE_STATUS_HEADER = "X-RESPONSE-STATUS";

    public static final String POST_AUTHENTICATION_SUCCESS_URI_HEADER = "X-POST-LOGIN-SUCCESS-URI";
    public static final String POST_AUTHENTICATION_SUCCESS_URI_PARAM = "post_login_success_uri";
    public static final String POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE = POST_AUTHENTICATION_SUCCESS_URI_PARAM;

    public static final String POST_AUTHENTICATION_FAILURE_URI_HEADER = "X-POST-LOGIN-FAILURE-URI";
    public static final String POST_AUTHENTICATION_FAILURE_URI_PARAM = "post_login_failure_uri";
    public static final String POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE = POST_AUTHENTICATION_FAILURE_URI_PARAM;
    public static final String POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE = "error";

    public static final String POST_LOGOUT_SUCCESS_URI_HEADER = "X-POST-LOGOUT-SUCCESS-URI";
    public static final String POST_LOGOUT_SUCCESS_URI_PARAM = "post_logout_success_uri";

    private List<String> securityMatchers = List.of();
    private URI clientUri = URI.create("/");
    private Optional<URI> postLoginRedirectHost = Optional.empty();
    private OAuth2RedirectionProperties oauth2Redirections = new OAuth2RedirectionProperties();
    private Csrf csrf = Csrf.DEFAULT;
    private List<String> permitAll = List.of("/login/**", "/oauth2/**");

    private Map<String, OAuth2LogoutProperties> oauth2Logout = new HashMap<>();

    /**
     * URI containing scheme, host and port where the user should be redirected after a successful logout (defaults to the client URI)
     */
    private Optional<URI> postLogoutRedirectHost = Optional.empty();

    /**
     * Path (relative to clientUri) where the user should be redirected after being logged out from authorization server(s)
     */
    private Optional<String> postLogoutRedirectPath = Optional.empty();

    public URI getPostLogoutRedirectHost() {
        return postLogoutRedirectHost.orElse(clientUri);
    }

    public URI getPostLogoutRedirectUri() {
        var uri = UriComponentsBuilder.fromUri(getPostLogoutRedirectHost());
        postLogoutRedirectPath.ifPresent(uri::path);

        return uri.build(Map.of());
    }

    @Data
    @ConfigurationProperties
    public static class OAuth2RedirectionProperties {
        private HttpStatus rpInitiatedLogout = HttpStatus.FOUND;
        private HttpStatus preAuthorizationCode = HttpStatus.FOUND;
        private HttpStatus postAuthorizationCode = HttpStatus.FOUND;
    }


    @Data
    @ConfigurationProperties
    public static class OAuth2LogoutProperties {

        /**
         * URI on the authorization server where to redirect the user for logout
         */
        private URI uri;

        /**
         * request param name for client-id
         */
        private Optional<String> clientIdRequestParam = Optional.empty();

        /**
         * request param name for post-logout redirect URI (where the user should be redirected after his session is closed on the authorization server)
         */
        private Optional<String> postLogoutUriRequestParam = Optional.empty();

        /**
         * request param name for setting an ID-Token hint
         */
        private Optional<String> idTokenHintRequestParam = Optional.empty();

        /**
         * RP-Initiated Logout is enabled by default. Setting this to false disables it.
         */
        private boolean enabled = true;
    }

    public Optional<OAuth2LogoutProperties> getLogoutProperties(String clientRegistrationId) {
        return Optional.ofNullable(oauth2Logout.get(clientRegistrationId));
    }
}
