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
            "AND s.credentialStatus = io.mosip.certify.entity.StatusListCredential$CredentialStatus.AVAILABLE " +
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

    /**
     * Find available status list credentials by purpose
     */
    List<StatusListCredential> findByStatusPurposeAndCredentialStatus(
            String statusPurpose,
            StatusListCredential.CredentialStatus credentialStatus);

    /**
     * Find status list credentials by credential type
     */
    List<StatusListCredential> findByCredentialType(String credentialType);

    /**
     * Find available status list credentials with capacity greater than specified value
     */
    @Query("SELECT s FROM StatusListCredential s WHERE s.credentialStatus = :status AND s.capacity > :minCapacity")
    List<StatusListCredential> findAvailableWithMinCapacity(
            @Param("status") StatusListCredential.CredentialStatus status,
            @Param("minCapacity") Long minCapacity);

    /**
     * Find the first available status list credential for a given purpose
     */
    Optional<StatusListCredential> findFirstByStatusPurposeAndCredentialStatusOrderByCreatedDtimesAsc(
            String statusPurpose,
            StatusListCredential.CredentialStatus credentialStatus);

    /**
     * Check if any available status list exists for a purpose
     */
    boolean existsByStatusPurposeAndCredentialStatus(
            String statusPurpose,
            StatusListCredential.CredentialStatus credentialStatus);

    /**
     * Count credentials by status
     */
    long countByCredentialStatus(StatusListCredential.CredentialStatus credentialStatus);

    /**
     * Count credentials by purpose and status
     */
    long countByStatusPurposeAndCredentialStatus(
            String statusPurpose,
            StatusListCredential.CredentialStatus credentialStatus);

    /**
     * Find capacity of status list by ID
     */
    @Query("SELECT s.capacity FROM StatusListCredential s WHERE s.id = :id")
    Optional<Long> findCapacityById(@Param("id") String id);
}