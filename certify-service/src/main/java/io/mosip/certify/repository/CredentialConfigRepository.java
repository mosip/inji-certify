package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CredentialConfigRepository extends JpaRepository<CredentialConfig, String> {
    Optional<CredentialConfig> findByCredentialFormatAndSdJwtVct(String credentialFormat, String sdJwtVct);
    Optional<CredentialConfig> findByCredentialFormatAndDocType(String credentialFormat, String docType);
    Optional<CredentialConfig> findByCredentialFormatAndCredentialTypeAndContext(String credentialFormat, String credentialType, String context);
    Optional<CredentialConfig> findByCredentialConfigKeyId(String credentialConfigKeyID);
}

