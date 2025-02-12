package com.ptopalidis.cecloud.bff.repository;

import com.ptopalidis.cecloud.bff.domain.CECloudSession;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface SessionRepository extends JpaRepository<CECloudSession, UUID> {

    Optional<CECloudSession> findByUserId(String userId);

    Optional<CECloudSession> findBySessionId(String sessionId);

    Optional<CECloudSession> findByKeycloakSession(String sessionId);
}
