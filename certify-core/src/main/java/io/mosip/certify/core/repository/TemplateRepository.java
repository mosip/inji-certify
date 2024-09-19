package io.mosip.certify.core.repository;

import io.mosip.certify.core.entity.TemplateData;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TemplateRepository extends JpaRepository<TemplateData, String> {
    Optional<TemplateData> findByCredentialTypeAndContext(String credentialType, String context);
    // NOTE: best practice? .save()
}

