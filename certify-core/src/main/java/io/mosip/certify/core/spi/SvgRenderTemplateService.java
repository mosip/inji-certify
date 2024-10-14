package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.SvgRenderTemplateDto;

public interface SvgRenderTemplateService {
    SvgRenderTemplateDto getSvgTemplate(String id);
}
