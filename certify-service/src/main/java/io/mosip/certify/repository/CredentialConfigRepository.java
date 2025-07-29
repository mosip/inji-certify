package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.TemplateId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CredentialConfigRepository extends JpaRepository<CredentialConfig, String> {
    Optional<CredentialConfig> findByCredentialTypeAndContext(String credentialType, String context);
    // NOTE: best practice? .save()
//    Optional<CredentialConfig> findByConfigId(String configId);
    void deleteByConfigId(String configId);
    Optional<CredentialConfig> findByCredentialFormatAndSdJwtVct(String credentialFormat, String sdJwtVct);
    Optional<CredentialConfig> findByCredentialFormatAndDocType(String credentialFormat, String docType);
    Optional<CredentialConfig> findByCredentialFormatAndCredentialTypeAndContext(String credentialFormat, String credentialType, String context);
}

