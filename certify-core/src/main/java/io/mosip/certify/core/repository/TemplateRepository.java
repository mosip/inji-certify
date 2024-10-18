package io.mosip.certify.core.repository;

import io.mosip.certify.core.entity.TemplateData;
import io.mosip.certify.core.entity.TemplateId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TemplateRepository extends JpaRepository<TemplateData, TemplateId> {
    Optional<TemplateData> findByCredentialTypeAndContext(String credentialType, String context);
    // NOTE: best practice? .save()
}

