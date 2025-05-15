package io.mosip.certify.repository;

import io.mosip.certify.entity.StatusListCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface StatusListCredentialRepository extends JpaRepository<StatusListCredential, String> {

    /**
     * Find a suitable status list credential that is available (not full) and matches the given purpose
     *
     * @param statusPurpose The purpose of the status list (e.g., "revocation", "suspension")
     * @return An optional containing the first available status list credential, or empty if none found
     */
    @Query("SELECT s FROM StatusListCredential s WHERE s.statusPurpose = :statusPurpose " +
            "AND s.credentialStatus = io.mosip.certify.entities.StatusListCredential.CredentialStatusEnum.AVAILABLE " +
            "ORDER BY s.createdDtimes DESC")
    Optional<StatusListCredential> findSuitableStatusList(@Param("statusPurpose") String statusPurpose);

    /**
     * Find all status list credentials for a specific purpose
     *
     * @param statusPurpose The purpose of the status list
     * @return List of status list credentials
     */
    List<StatusListCredential> findByStatusPurpose(String statusPurpose);

    /**
     * Find all status list credentials with a specific credential status
     *
     * @param credentialStatus The status of the credential (AVAILABLE or FULL)
     * @return List of status list credentials
     */
    List<StatusListCredential> findByCredentialStatus(StatusListCredential.CredentialStatus credentialStatus);
}