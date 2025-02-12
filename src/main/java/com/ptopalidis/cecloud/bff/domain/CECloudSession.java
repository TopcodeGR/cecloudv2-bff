package com.ptopalidis.cecloud.bff.domain;


import jakarta.persistence.*;
import lombok.*;


import java.util.UUID;

@Data
@Builder
@Table(name = "cecloud_session")
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class CECloudSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "session_id")
    private String sessionId;

    @Column(name = "access_token")
    private String accessToken;

    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(name = "keycloak_session")
    private String keycloakSession;

    @Column(name = "id_token")
    private String idToken;

    @Column(name = "user_id")
    private String userId;
}
