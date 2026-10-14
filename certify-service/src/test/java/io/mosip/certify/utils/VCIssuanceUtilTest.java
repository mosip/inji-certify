package io.mosip.certify.utils;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VCIssuanceUtilTest {

    private CredentialConfigurationSupported config(String format, List<String> bindingMethods, Map<String, Object> proofTypes) {
        CredentialConfigurationSupported config = new CredentialConfigurationSupported();
        config.setFormat(format);
        config.setCryptographicBindingMethodsSupported(bindingMethods);
        config.setProofTypesSupported(proofTypes);
        return config;
    }

    private static final Map<String, Object> JWT_PROOF_TYPES =
            Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256")));

    @Test
    public void requiresProof_whenBindingMethodsAndProofTypesArePresent() {
        assertTrue(VCIssuanceUtil.requiresProof(config(VCFormats.LDP_VC, List.of("did:jwk"), JWT_PROOF_TYPES)));
    }

    @Test
    public void doesNotRequireProof_whenBindingMethodsAndProofTypesAreBothAbsentOrEmpty() {
        assertFalse(VCIssuanceUtil.requiresProof(config(VCFormats.LDP_VC, null, null)));
        assertFalse(VCIssuanceUtil.requiresProof(config(VCFormats.DC_SD_JWT, List.of(), Collections.emptyMap())));
    }

    /**
     * The API never stores only one of the two attributes, but a row edited to declare only one still
     * requires a proof rather than being issued without holder binding.
     */
    @Test
    public void requiresProof_whenOnlyOneOfBindingMethodsAndProofTypesIsPresent() {
        assertTrue(VCIssuanceUtil.requiresProof(config(VCFormats.LDP_VC, null, JWT_PROOF_TYPES)));
        assertTrue(VCIssuanceUtil.requiresProof(config(VCFormats.DC_SD_JWT, List.of(), JWT_PROOF_TYPES)));
        assertTrue(VCIssuanceUtil.requiresProof(config(VCFormats.LDP_VC, List.of("did:jwk"), null)));
        assertTrue(VCIssuanceUtil.requiresProof(config(VCFormats.DC_SD_JWT, List.of("did:jwk"), Collections.emptyMap())));
    }

    @Test
    public void requiresProof_forMsoMdocEvenWithoutBindingMetadata() {
        assertTrue(VCIssuanceUtil.requiresProof(config(VCFormats.MSO_MDOC, null, null)));
    }
}
