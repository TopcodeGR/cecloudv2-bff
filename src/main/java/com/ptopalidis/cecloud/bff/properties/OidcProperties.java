package com.ptopalidis.cecloud.bff.properties;


import lombok.Data;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import java.net.URI;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "oidc")
public class OidcProperties {


    private List<OpenidProviderProperties> ops = List.of();

    @NestedConfigurationProperty
    private OidcClientProperties client = new OidcClientProperties();

    @NestedConfigurationProperty
    private OidcResourceServerProperties resourceServer = new OidcResourceServerProperties();

    private List<CorsProperties> cors = List.of();


    @Data
    @ConfigurationProperties
    static public class OpenidProviderProperties {

        private URI iss;

        private URI jwkSetUri;

        private String aud;

        private List<SimpleAuthoritiesMappingProperties> authorities = List.of();

        private String usernameClaim = StandardClaimNames.SUB;

        @Data
        @ConfigurationProperties
        public static class SimpleAuthoritiesMappingProperties {

            private String path = "$.realm_access.roles";


            private String prefix = "";

            private Case caze = Case.UNCHANGED;

            public static enum Case {
                UNCHANGED,
                UPPER,
                LOWER
            }

        }
    }


}
