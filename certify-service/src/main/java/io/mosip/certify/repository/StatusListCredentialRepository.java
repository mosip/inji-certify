package io.mosip.certify.repository;

import io.mosip.certify.entity.StatusListCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface StatusListCredentialRepository extends JpaRepository<StatusListCredential, String> {
    
    List<StatusListCredential> findByIssuerId(String issuerId);
    
    List<StatusListCredential> findByStatusPurpose(String statusPurpose);
    
    Optional<StatusListCredential> findByIssuerIdAndStatusPurpose(String issuerId, String statusPurpose);
    
    @Query("SELECT slc FROM StatusListCredential slc WHERE slc.validFrom <= :date AND (slc.validUntil IS NULL OR slc.validUntil >= :date)")
    List<StatusListCredential> findValidStatusListsAtDate(@Param("date") LocalDateTime date);
    
    @Query("SELECT slc FROM StatusListCredential slc WHERE slc.issuerId = :issuerId AND slc.validFrom <= :date AND (slc.validUntil IS NULL OR slc.validUntil >= :date)")
    List<StatusListCredential> findValidStatusListsByIssuerAtDate(@Param("issuerId") String issuerId, @Param("date") LocalDateTime date);
    
    @Query("SELECT slc FROM StatusListCredential slc WHERE slc.issuerId = :issuerId AND slc.statusPurpose = :purpose AND slc.validFrom <= :date AND (slc.validUntil IS NULL OR slc.validUntil >= :date)")
    Optional<StatusListCredential> findValidStatusListByIssuerAndPurposeAtDate(@Param("issuerId") String issuerId, @Param("purpose") String purpose, @Param("date") LocalDateTime date);
}