package io.mosip.certify.services;

import io.mosip.certify.api.spi.VCModifier;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@ConditionalOnProperty(name = "mosip.certify.issuer.modifier.enabled", havingValue = "NoOp")
public class NoOpVCModifier implements VCModifier {
    @Override
    public JSONObject perform(String templateInput) {
        try {
           JSONObject j = new JSONObject(templateInput);
           return j;
        } catch (JSONException e) {
            log.error("Received JSON: " + templateInput);
            log.error(e.getMessage());
            throw new CertifyException(ErrorConstants.JSON_TEMPLATING_ERROR);
        }
    }
}
