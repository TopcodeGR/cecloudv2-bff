package com.ptopalidis.cecloud.bff.service;


import com.ptopalidis.cecloud.bff.domain.CECloudSession;
import com.ptopalidis.cecloud.bff.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CECloudSessionService {

    private final SessionRepository sessionRepository;


    @Transactional
    public CECloudSession createSession(CECloudSession CECloudSession) {
        return sessionRepository.save(CECloudSession);
    }

    @Transactional
    public void deleteSession(CECloudSession session) {
        sessionRepository.delete(session);
    }

    public Optional<CECloudSession> getSessionBySessionId(String sessionId) {
        return sessionRepository.findBySessionId(sessionId);
    }

    public Optional<CECloudSession> getSessionByKeycloakSession(String keycloakSessionid) {
        return sessionRepository.findByKeycloakSession(keycloakSessionid);
    }


    public Optional<CECloudSession> getSessionByUserId(String userId) {
        return sessionRepository.findByUserId(userId);
    }

}
