package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CredentialConfigRepository extends JpaRepository<CredentialConfig, String> {
}
