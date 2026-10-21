package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.entity.CredentialConfig;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Reads what the deployment declares for cryptographic_binding_methods_supported and
 * proof_types_supported, and resolves the values a stored credential configuration advertises.
 * <p>
 * A configuration written through the API always stores both, and they are advertised as stored.
 * Configurations created before these attributes were stored carry no value, and are resolved from the
 * deployment configuration so they keep advertising what they always have, with no data migration.
 * credential_signing_alg_values_supported is never resolved from the deployment configuration: it is
 * read from the configuration's own crypto suite or signatureAlgo. Nothing here is used to fill in a
 * value on write.
 * <p>
 * This is the counterpart to CredentialConfigMetadataValidator: this class answers what the deployment
 * declares, the validator answers whether a requested value is among them. The declared values are
 * passed in rather than injected, so both remain pure functions of request and configuration.
 */
public class CredentialConfigMetadataResolver {

    private CredentialConfigMetadataResolver() {
    }

    /**
     * The binding methods declared for a credential format, empty when the deployment declares none.
     */
    public static List<String> deriveBindingMethods(String credentialFormat,
                                                    Map<String, List<String>> declaredBindingMethodsByFormat) {
        List<String> declared = declaredBindingMethodsByFormat.get(credentialFormat);
        return declared == null ? new ArrayList<>() : new ArrayList<>(declared);
    }

    /**
     * What a configuration advertises in credential_signing_alg_values_supported, which is also what is
     * stored for it: the one value it is signed with, taken from the configuration alone and never from
     * the deployment configuration.
     * <p>
     * An ldp_vc configuration advertises its crypto suite, such as Ed25519Signature2020 or
     * eddsa-rdfc-2022, per OpenID4VCI 1.0 Appendix A.1.2.2, since a JWS algorithm alone can stand for
     * several suites. Every other format, and an ldp_vc configuration with no crypto suite, advertises its
     * signatureAlgo. Because both are read from the configuration itself, an existing configuration
     * advertises them without being re-submitted.
     */
    public static List<String> resolveAdvertisedSigningAlgs(CredentialConfig credentialConfig) {
        String signatureCryptoSuite = credentialConfig.getSignatureCryptoSuite();
        String advertised = VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())
                && signatureCryptoSuite != null && !signatureCryptoSuite.isEmpty()
                ? signatureCryptoSuite
                : credentialConfig.getSignatureAlgo();
        return advertised == null || advertised.isEmpty() ? new ArrayList<>() : new ArrayList<>(List.of(advertised));
    }

    /**
     * Fills in proof_signing_alg_values_supported for a stored proof type that carries none, so that what
     * is advertised always carries the algorithms the deployment declares for that proof type. Only a
     * configuration created before these attributes were mandatory can hold such a proof type.
     * <p>
     * Advertising the bare proof type instead would publish it with no algorithms, which OpenID4VCI does
     * not allow, and JwtProofValidator reads a missing list as an empty one and rejects every proof, so
     * the configuration would silently stop issuing.
     * <p>
     * A proof type left with no algorithms at all - the deployment declares none for it, so there is
     * nothing to fill in with - has exactly that effect, so it is rejected here rather than advertised.
     * That is a deployment misconfiguration in mosip.certify.credential-config.proof-types-supported.
     *
     * @throws IllegalStateException when a proof type resolves to an empty list of signing algorithms
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> resolveProofTypes(Map<String, Object> proofTypes,
                                                        Map<String, Object> declaredProofTypes) {
        Map<String, Object> resolved = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : proofTypes.entrySet()) {
            Object detail = entry.getValue();
            Map<String, Object> detailMap = detail instanceof Map
                    ? new LinkedHashMap<>((Map<String, Object>) detail)
                    : new LinkedHashMap<>();
            detailMap.computeIfAbsent(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED,
                    attribute -> declaredProofSigningAlgs(declaredProofTypes, entry.getKey()));

            Object signingAlgs = detailMap.get(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED);
            if (!(signingAlgs instanceof Collection) || ((Collection<?>) signingAlgs).isEmpty()) {
                throw new IllegalStateException("No " + Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED
                        + " is available for the proof type " + entry.getKey()
                        + ". Declare it for that proof type in mosip.certify.credential-config.proof-types-supported.");
            }
            resolved.put(entry.getKey(), detailMap);
        }
        return resolved;
    }

    /**
     * The proof signing algorithms the deployment declares for a proof type, empty when it declares none.
     */
    @SuppressWarnings("unchecked")
    public static List<String> declaredProofSigningAlgs(Map<String, Object> declaredProofTypes, String proofType) {
        Object declaredDetail = declaredProofTypes.get(proofType);
        if (declaredDetail instanceof Map) {
            Object declaredAlgs = ((Map<String, Object>) declaredDetail).get(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED);
            if (declaredAlgs instanceof Collection) {
                return ((Collection<?>) declaredAlgs).stream().map(String::valueOf).collect(Collectors.toList());
            }
        }
        return Collections.emptyList();
    }
}
