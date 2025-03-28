package io.mosip.certify.repository;

import io.mosip.certify.entity.LedgerIssuanceTable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface LedgerIssuanceTableRepository extends JpaRepository<LedgerIssuanceTable, String> {
    
    Optional<LedgerIssuanceTable> findByCredentialId(String credentialId);
    
    List<LedgerIssuanceTable> findByIssuerId(String issuerId);
    
    List<LedgerIssuanceTable> findByCredentialStatus(String status);
    
    List<LedgerIssuanceTable> findByStatusPurpose(String statusPurpose);
    
    Optional<LedgerIssuanceTable> findByCredentialIdAndIssuerId(String credentialId, String issuerId);
    
    List<LedgerIssuanceTable> findByIssuerIdAndStatusPurpose(String issuerId, String statusPurpose);
    
    List<LedgerIssuanceTable> findByIssuerIdAndCredentialStatus(String issuerId, String status);
    
    @Query("SELECT cs FROM LedgerIssuanceTable cs WHERE cs.issueDate <= :date AND (cs.expirationDate IS NULL OR cs.expirationDate >= :date)")
    List<LedgerIssuanceTable> findValidCredentialsAtDate(@Param("date") LocalDateTime date);
    
    @Query("SELECT cs FROM LedgerIssuanceTable cs WHERE cs.credentialStatus = 'valid' AND cs.expirationDate <= :date")
    List<LedgerIssuanceTable> findExpiredCredentials(@Param("date") LocalDateTime date);
}