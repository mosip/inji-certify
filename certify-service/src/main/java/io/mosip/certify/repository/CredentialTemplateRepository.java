package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialTemplate;
import io.mosip.certify.entity.TemplateId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CredentialTemplateRepository extends JpaRepository<CredentialTemplate, TemplateId> {
    Optional<CredentialTemplate> findByCredentialTypeAndContext(String credentialType, String context);
    // NOTE: best practice? .save()
}

