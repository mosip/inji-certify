package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialHolder;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialHolderRepository extends JpaRepository<CredentialHolder, String> {
    
    Optional<CredentialHolder> findByCredentialId(String credentialId);
    
    List<CredentialHolder> findByHolderId(String holderId);
    
    List<CredentialHolder> findByCredentialType(String credentialType);
    
    List<CredentialHolder> findByHolderIdAndCredentialType(String holderId, String credentialType);
    
    boolean existsByCredentialId(String credentialId);
}