package io.mosip.certify.repository;

import io.mosip.certify.entity.IarSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface IarSessionRepository extends JpaRepository<IarSession, Long> {
    Optional<IarSession> findByAuthSession(String authSession);
    Optional<IarSession> findByAuthorizationCode(String authorizationCode);
    
    /**
     * Atomically mark authorization code as used to prevent race conditions
     * Only updates if the code is not already used (isCodeUsed = false)
     * Returns the number of rows updated (0 if already used, 1 if successfully updated)
     */
    @Modifying
    @Transactional
    @Query("UPDATE IarSession s SET s.isCodeUsed = true, s.codeUsedAt = :usedAt WHERE s.authorizationCode = :authorizationCode AND s.isCodeUsed = false")
    int markAuthorizationCodeAsUsed(@Param("authorizationCode") String authorizationCode, @Param("usedAt") LocalDateTime usedAt);
}


