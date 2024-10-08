package com.ptopalidis.cecloud.bff.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties

public class OidcResourceServerProperties {
    /**
     * Resource server SecurityFilterChain bean and all its dependencies are instantiated only if true.
     */
    private boolean enabled = true;

    /**
     * Path matchers for the routes accessible to anonymous requests
     */
    private List<String> permitAll = List.of();

    /**
     * Whether to disable sessions. It should remain true.
     */
    private boolean statlessSessions = true;

    /**
     * CSRF protection configuration for the auto-configured client filter-chain
     */
    private Csrf csrf = Csrf.DISABLE;

}
