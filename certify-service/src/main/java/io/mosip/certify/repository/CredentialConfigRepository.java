package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.TemplateId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CredentialConfigRepository extends JpaRepository<CredentialConfig, TemplateId> {
    Optional<CredentialConfig> findByCredentialTypeAndContext(String credentialType, String context);
    // NOTE: best practice? .save()
    Optional<CredentialConfig> findByConfigId(String configId);
    void deleteByConfigId(String configId);
}

