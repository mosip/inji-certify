package io.mosip.certify.repository;

import io.mosip.certify.entity.IarSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IarSessionRepository extends JpaRepository<IarSession, Long> {
    Optional<IarSession> findByAuthSession(String authSession);
    Optional<IarSession> findByAuthorizationCode(String authorizationCode);
}


