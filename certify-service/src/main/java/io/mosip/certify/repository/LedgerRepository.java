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


    /**
     * Search by indexed attributes using JSONB containment
     * This will find records where indexed_attributes contains all the key-value pairs in the search criteria
     */
    @Query(value = "SELECT * FROM ledger WHERE indexed_attributes @> CAST(:searchJson AS jsonb)",
            nativeQuery = true)
    List<Ledger> findByIndexedAttributesContaining(@Param("searchJson") String searchJson);

    /**
     * Search by specific key-value pair in indexed attributes
     */
    @Query(value = "SELECT * FROM ledger WHERE indexed_attributes ->> :key = :value",
            nativeQuery = true)
    List<Ledger> findByIndexedAttributeKeyValue(@Param("key") String key, @Param("value") String value);

    /**
     * Find all active (non-expired) credentials
     */
    @Query("SELECT l FROM Ledger l WHERE l.expirationDate IS NULL OR l.expirationDate > :currentDate")
    List<Ledger> findActiveCredentials(@Param("currentDate") OffsetDateTime currentDate);

    /**
     * Complex search combining multiple criteria
     */
    @Query(value = """
        SELECT * FROM ledger l 
        WHERE (:issuerId IS NULL OR l.issuer_id = :issuerId)
        AND (:credentialType IS NULL OR l.credential_type = :credentialType)
        AND (:searchJson IS NULL OR l.indexed_attributes @> CAST(:searchJson AS jsonb))
        """, nativeQuery = true)
    List<Ledger> searchWithCriteria(
            @Param("issuerId") String issuerId,
            @Param("credentialType") String credentialType,
            @Param("searchJson") String searchJson
    );
}