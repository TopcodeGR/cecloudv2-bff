package com.ptopalidis.cecloud.bff.properties;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class ByIssuerOpenidProviderPropertiesResolver implements OpenidProviderPropertiesResolver{

    private final OidcProperties oidcProperties;

    @Override
    public Optional<OidcProperties.OpenidProviderProperties> resolve(Map<String, Object> claimSet) {
        final var iss = Optional.ofNullable(claimSet.get(JwtClaimNames.ISS)).map(Object::toString).orElse(null);
        return oidcProperties
                .getOps()
                .stream()
                .filter(issuerProps -> Objects.equals(Optional.ofNullable(issuerProps.getIss()).map(URI::toString).orElse(null), iss))
                .findAny();
    }
}
