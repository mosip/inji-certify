package io.mosip.certify.core.spi;

import io.mosip.certify.core.entity.SvgRenderTemplate;

import java.util.UUID;

public interface SvgRenderTemplateService {
    SvgRenderTemplate getSvgTemplate(UUID id);
}
