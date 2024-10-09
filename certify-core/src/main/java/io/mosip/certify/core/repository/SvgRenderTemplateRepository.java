package io.mosip.certify.core.repository;

import io.mosip.certify.core.entity.SvgRenderTemplate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface SvgRenderTemplateRepository extends JpaRepository<SvgRenderTemplate, UUID> {
}
