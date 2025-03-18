package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialStatusRepository extends JpaRepository<CredentialStatus, String> {
    
    Optional<CredentialStatus> findByCredentialId(String credentialId);
    
    List<CredentialStatus> findByIssuerId(String issuerId);
    
    List<CredentialStatus> findByCredentialStatus(String status);
    
    List<CredentialStatus> findByStatusPurpose(String statusPurpose);
    
    Optional<CredentialStatus> findByCredentialIdAndIssuerId(String credentialId, String issuerId);
    
    List<CredentialStatus> findByIssuerIdAndStatusPurpose(String issuerId, String statusPurpose);
    
    List<CredentialStatus> findByIssuerIdAndCredentialStatus(String issuerId, String status);
    
    @Query("SELECT cs FROM CredentialStatus cs WHERE cs.issueDate <= :date AND (cs.expirationDate IS NULL OR cs.expirationDate >= :date)")
    List<CredentialStatus> findValidCredentialsAtDate(@Param("date") LocalDateTime date);
    
    @Query("SELECT cs FROM CredentialStatus cs WHERE cs.credentialStatus = 'valid' AND cs.expirationDate <= :date")
    List<CredentialStatus> findExpiredCredentials(@Param("date") LocalDateTime date);
}