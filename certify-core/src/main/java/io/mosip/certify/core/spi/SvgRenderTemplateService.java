package io.mosip.certify.core.spi;

import io.mosip.certify.api.exception.VCIExchangeException;

import java.io.IOException;
import java.util.UUID;

public interface SvgRenderTemplateService {
    String getSvgTemplate(UUID id);
}
