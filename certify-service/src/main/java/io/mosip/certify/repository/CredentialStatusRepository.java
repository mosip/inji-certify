package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import javax.persistence.LockModeType;
import java.util.List;
import java.util.Optional;

/**
 * Repository for CredentialStatus entity
 */
@Repository
public interface CredentialStatusRepository extends JpaRepository<CredentialStatus, Long> {

    /**
     * Find credential status by credential ID with pessimistic lock for update
     *
     * @param credentialId the credential ID
     * @return optional credential status
     */
    @Query("SELECT cs FROM CredentialStatus cs WHERE cs.ledgerId = :credentialId")
    Optional<CredentialStatus> findByCredentialIdForUpdate(@Param("credentialId") String credentialId);

    /**
     * Find all credential status entries for a specific status list credential ID
     *
     * @param statusListCredentialId the status list credential ID
     * @return list of credential status entries
     */
    List<CredentialStatus> findByStatusListCredentialId(String statusListCredentialId);
}