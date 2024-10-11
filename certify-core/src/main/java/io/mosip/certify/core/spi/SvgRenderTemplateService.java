package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.SvgRenderTemplateDto;

import java.util.UUID;

public interface SvgRenderTemplateService {
    SvgRenderTemplateDto getSvgTemplate(UUID id);
}
