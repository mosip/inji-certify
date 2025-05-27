package io.mosip.certify.repository;

import io.mosip.certify.entity.Ledger;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface LedgerRepository extends JpaRepository<Ledger, Long> {

    Optional<Ledger> findByCredentialId(String credentialId);
    List<Ledger> findByIssuerId(String issuerId);
    Page<Ledger> findByIssuerId(String issuerId, Pageable pageable);
    List<Ledger> findByCredentialType(String credentialType);
    List<Ledger> findByIssueDateBetween(OffsetDateTime startDate, OffsetDateTime endDate);
    List<Ledger> findByExpirationDateBetween(OffsetDateTime startDate, OffsetDateTime endDate);
    List<Ledger> findByExpirationDateBefore(OffsetDateTime date);
    List<Ledger> findByIssuerIdAndCredentialType(String issuerId, String credentialType);
    List<Ledger> findByCreatedDtimesBetween(OffsetDateTime startDate, OffsetDateTime endDate);
    boolean existsByCredentialId(String credentialId);
    long countByIssuerId(String issuerId);
    long countByCredentialType(String credentialType);

    /**
     * Find credentials with specific indexed attributes using JSON queries
     * Note: This is PostgreSQL specific - adjust syntax for other databases
     */
    @Query(value = "SELECT * FROM ledger WHERE indexed_attributes @> CAST(:attributeJson AS jsonb)",
            nativeQuery = true)
    List<Ledger> findByIndexedAttributesContaining(@Param("attributeJson") String attributeJson);

    /**
     * Find credentials by JSON path in indexed attributes
     */
    @Query(value = "SELECT * FROM ledger WHERE indexed_attributes ->> :key = :value",
            nativeQuery = true)
    List<Ledger> findByIndexedAttributeKeyValue(@Param("key") String key, @Param("value") String value);

    /**
     * Find all active (non-expired) credentials
     */
    @Query("SELECT l FROM Ledger l WHERE l.expirationDate IS NULL OR l.expirationDate > :currentDate")
    List<Ledger> findActiveCredentials(@Param("currentDate") OffsetDateTime currentDate);
}