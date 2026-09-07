package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VCApiIssueOptions;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiIssuanceService {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private VCApiCredentialIssuer vcApiCredentialIssuer;

    public Map<String, Object> issue(VCApiIssueRequest request, String credentialConfigurationId) {
        log.info("VC API issue request for configuration: {}", credentialConfigurationId);
        rejectUnsupportedOptions(request.getOptions());

        try {
            CredentialConfigurationDTO config = credentialConfigurationService
                    .getCredentialConfigurationById(credentialConfigurationId);

            VCApiCredentialIssuer.VCApiIssueResult result = vcApiCredentialIssuer
                    .issueValidatedCredential(request.getCredential(), config);

            return toCredentialMap(result.verifiableCredential());
        } catch (CredentialConfigException e) {
            throw new CertifyException(e.getErrorCode(), e.getMessage(), e);
        }
    }

    /**
     * Proof-hint options ({@code challenge}, {@code domain}, {@code verificationMethod}, etc.)
     * are not applied by Certify signing. A non-empty value is hard-rejected with
     * {@code UNKNOWN_OPTION_PROVIDED} so clients do not receive a signed VC that silently
     * omits requested proof fields. Null or empty {@code options} is accepted for W3C shape
     * compatibility.
     */
    private void rejectUnsupportedOptions(VCApiIssueOptions options) {
        if (options == null) {
            return;
        }
        if (StringUtils.isNotBlank(options.getType())
                || StringUtils.isNotBlank(options.getVerificationMethod())
                || StringUtils.isNotBlank(options.getProofPurpose())
                || StringUtils.isNotBlank(options.getCreated())
                || StringUtils.isNotBlank(options.getChallenge())
                || StringUtils.isNotBlank(options.getDomain())) {
            throw new CertifyException(ErrorConstants.UNKNOWN_OPTION_PROVIDED,
                    "VC API issue options proof hints are not supported; omit options or pass an empty object");
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> toCredentialMap(JsonLDObject jsonLDObject) {
        Object json = jsonLDObject.getJsonObject();
        if (json instanceof Map<?, ?> map) {
            return new LinkedHashMap<>((Map<String, Object>) map);
        }
        throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                "Unable to convert verifiable credential to response format");
    }
}
