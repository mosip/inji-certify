package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialStatusTransaction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface CredentialStatusTransactionRepository extends JpaRepository<CredentialStatusTransaction, Long> {

    List<CredentialStatusTransaction> findByCredentialIdOrderByCreatedDtimesDesc(String credentialId);
    Page<CredentialStatusTransaction> findByCredentialIdOrderByCreatedDtimesDesc(String credentialId, Pageable pageable);
    List<CredentialStatusTransaction> findByStatusPurpose(String statusPurpose);
    List<CredentialStatusTransaction> findByStatusValue(Boolean statusValue);
    List<CredentialStatusTransaction> findByStatusListCredentialId(String statusListCredentialId);
    List<CredentialStatusTransaction> findByCreatedDtimesBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<CredentialStatusTransaction> findByCredentialIdAndStatusPurposeOrderByCreatedDtimesDesc(
            String credentialId, String statusPurpose);
    long countByCredentialId(String credentialId);
    long countByStatusPurpose(String statusPurpose);
    List<CredentialStatusTransaction> findByStatusListCredentialIdAndStatusListIndex(
            String statusListCredentialId, Long statusListIndex);

    /**
     * Find latest transaction for a credential
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.credentialId = :credentialId " +
            "ORDER BY t.createdDtimes DESC LIMIT 1")
    CredentialStatusTransaction findLatestByCredentialId(@Param("credentialId") String credentialId);

    /**
     * Find latest transaction for a credential with specific purpose
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.credentialId = :credentialId " +
            "AND t.statusPurpose = :statusPurpose ORDER BY t.createdDtimes DESC LIMIT 1")
    CredentialStatusTransaction findLatestByCredentialIdAndStatusPurpose(
            @Param("credentialId") String credentialId,
            @Param("statusPurpose") String statusPurpose);

    /**
     * Find all revoked credentials (status_value = true for revocation purpose)
     */
    @Query("SELECT DISTINCT t.credentialId FROM CredentialStatusTransaction t " +
            "WHERE t.statusPurpose = 'revocation' AND t.statusValue = true")
    List<String> findRevokedCredentialIds();

    /**
     * Find recent transactions (last N days)
     */
    @Query("SELECT t FROM CredentialStatusTransaction t WHERE t.createdDtimes >= :sinceDate " +
            "ORDER BY t.createdDtimes DESC")
    List<CredentialStatusTransaction> findRecentTransactions(@Param("sinceDate") LocalDateTime sinceDate);
}