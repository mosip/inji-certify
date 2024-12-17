package io.mosip.certify.services.repository;

import io.mosip.certify.services.entity.CredentialTemplate;
import io.mosip.certify.services.entity.TemplateId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TemplateRepository extends JpaRepository<CredentialTemplate, TemplateId> {
    Optional<CredentialTemplate> findByCredentialTypeAndContext(String credentialType, String context);
    // NOTE: best practice? .save()
}

