package io.mosip.certify.services;

import io.mosip.certify.api.dto.VCRequestDto;

public interface VCIPluginSelecter {
    PluginType choosePlugin(VCRequestDto r);
}
