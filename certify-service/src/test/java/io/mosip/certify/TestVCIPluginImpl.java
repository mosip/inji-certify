package io.mosip.certify;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Map;

@ConditionalOnProperty(value = "mosip.certify.integration.vci-plugin", havingValue = "TestVCIPluginImpl")
@Component
@Slf4j
public class TestVCIPluginImpl implements VCIssuancePlugin {

    @Override
    public VCResult<JsonLDObject> getVerifiableCredentialWithLinkedDataProof(VCRequestDto vcRequestDto, String holderId,
                                                                             Map<String, Object> identityDetails) {
        return new VCResult<>();
    }

    @Override
    public VCResult<String> getVerifiableCredential(VCRequestDto vcRequestDto, String holderId, Map<String, Object> identityDetails) {
        return new VCResult<>();
    }
}