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
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Reads what the deployment declares for cryptographic_binding_methods_supported,
 * credential_signing_alg_values_supported and proof_types_supported, and resolves the values a stored
 * credential configuration advertises.
 * <p>
 * A configuration written through the API always stores all three, and they are advertised as stored.
 * Configurations created before these attributes were stored carry no value, or a crypto suite name in
 * place of the signing algorithms, and are resolved from the deployment configuration so they keep
 * advertising what they always have, with no data migration. Nothing here is used to fill in a value
 * on write.
 * <p>
 * This is the counterpart to CredentialConfigMetadataValidator: this class answers what the deployment
 * declares, the validator answers whether a requested value is among them. The declared values are
 * passed in rather than injected, so both remain pure functions of request and configuration.
 */
public class CredentialConfigMetadataResolver {

    private static final Set<String> SIGNING_ALG_FORMATS = Set.of(VCFormats.LDP_VC, VCFormats.MSO_MDOC, VCFormats.DC_SD_JWT);

    private CredentialConfigMetadataResolver() {
    }

    /**
     * mosip.certify.credential-config.credential-signing-alg-values-supported, read as two lookups: the
     * algorithms declared for each crypto suite, and the algorithms declared for each credential format
     * that carries no crypto suite of its own.
     */
    public record DeclaredSigningAlgs(Map<String, List<String>> byCryptoSuite, Map<String, List<String>> byFormat) {
    }

    /**
     * Reads mosip.certify.credential-config.credential-signing-alg-values-supported in either of its shapes.
     * <p>
     * Grouped by credential format, the ldp_vc entry maps each crypto suite to its algorithms and the
     * mso_mdoc and dc+sd-jwt entries each list their algorithms:
     * <pre>
     * {'ldp_vc': {'Ed25519Signature2020': {'EdDSA'}, ...}, 'mso_mdoc': {'ES256'}, 'dc+sd-jwt': {'ES256', 'EdDSA'}}
     * </pre>
     * Keyed by crypto suite only, the original shape, the whole value maps each crypto suite to its
     * algorithms and no format declares a list of its own:
     * <pre>
     * {'Ed25519Signature2020': {'EdDSA'}, 'EcdsaSecp256r1Signature2019': {'ES256'}, ...}
     * </pre>
     * The shape is recognised by its top-level keys, so a deployment can move to the grouped shape at its
     * own pace.
     *
     * @throws IllegalStateException when the property is malformed, so a deployment fails at startup
     * rather than accepting configurations it cannot validate
     */
    public static DeclaredSigningAlgs parseDeclaredSigningAlgs(Map<String, ?> declared) {
        Map<String, List<String>> byCryptoSuite = new LinkedHashMap<>();
        Map<String, List<String>> byFormat = new LinkedHashMap<>();
        if (declared == null) {
            return new DeclaredSigningAlgs(byCryptoSuite, byFormat);
        }

        boolean groupedByFormat = declared.keySet().stream().anyMatch(SIGNING_ALG_FORMATS::contains);
        if (!groupedByFormat) {
            declared.forEach((cryptoSuite, algs) -> byCryptoSuite.put(cryptoSuite, toAlgList(cryptoSuite, algs)));
            return new DeclaredSigningAlgs(byCryptoSuite, byFormat);
        }

        declared.forEach((format, value) -> {
            if (!SIGNING_ALG_FORMATS.contains(format)) {
                throw new IllegalStateException("credential-signing-alg-values-supported is grouped by credential format, but "
                        + format + " is not a credential format. The supported keys are: " + SIGNING_ALG_FORMATS);
            }
            if (VCFormats.LDP_VC.equals(format)) {
                if (!(value instanceof Map<?, ?> suites)) {
                    throw new IllegalStateException("credential-signing-alg-values-supported for " + VCFormats.LDP_VC
                            + " must map each crypto suite to its algorithms.");
                }
                suites.forEach((cryptoSuite, algs) ->
                        byCryptoSuite.put(String.valueOf(cryptoSuite), toAlgList(String.valueOf(cryptoSuite), algs)));
            } else {
                byFormat.put(format, toAlgList(format, value));
            }
        });
        return new DeclaredSigningAlgs(byCryptoSuite, byFormat);
    }

    private static List<String> toAlgList(String key, Object algs) {
        if (!(algs instanceof Collection<?> values)) {
            throw new IllegalStateException("credential-signing-alg-values-supported for " + key + " must be a list of algorithms.");
        }
        return values.stream().map(String::valueOf).collect(Collectors.toList());
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
     * The algorithms declared for the crypto suite, rather than the crypto suite name itself, so that
     * what is advertised is an algorithm value such as EdDSA and not a suite such as Ed25519Signature2020.
     */
    public static List<String> deriveSigningAlgs(String signatureCryptoSuite, String signatureAlgo,
                                                 Map<String, List<String>> declaredSigningAlgsByCryptoSuite) {
        if (signatureCryptoSuite != null) {
            List<String> declared = declaredSigningAlgsByCryptoSuite.get(signatureCryptoSuite);
            if (declared != null) {
                return new ArrayList<>(declared);
            }
        }
        return signatureAlgo == null ? new ArrayList<>() : new ArrayList<>(List.of(signatureAlgo));
    }

    /**
     * What a configuration advertises in credential_signing_alg_values_supported, which is also what is
     * stored for it: the one value it is signed with.
     * <p>
     * An ldp_vc configuration advertises its crypto suite, such as Ed25519Signature2020 or
     * eddsa-rdfc-2022, per OpenID4VCI 1.0 Appendix A.1.2.2, since a JWS algorithm alone can stand for
     * several suites. Every other format advertises its signatureAlgo. A configuration created before
     * signatureAlgo was mandatory may carry none, and keeps advertising what it always has.
     */
    public static List<String> resolveAdvertisedSigningAlgs(CredentialConfig credentialConfig,
                                                            Map<String, List<String>> declaredSigningAlgsByCryptoSuite) {
        String signatureCryptoSuite = credentialConfig.getSignatureCryptoSuite();
        if (VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())
                && signatureCryptoSuite != null && !signatureCryptoSuite.isEmpty()) {
            return new ArrayList<>(List.of(signatureCryptoSuite));
        }
        String signatureAlgo = credentialConfig.getSignatureAlgo();
        if (signatureAlgo != null && !signatureAlgo.isEmpty()) {
            return new ArrayList<>(List.of(signatureAlgo));
        }
        return resolveStoredSigningAlgs(credentialConfig, declaredSigningAlgsByCryptoSuite);
    }

    /**
     * Reads the stored signing algorithms, translating the crypto suite names written by configurations
     * created before those values were stored as algorithms. Existing configurations therefore keep
     * advertising exactly what they advertised before, with no data migration.
     */
    public static List<String> resolveStoredSigningAlgs(CredentialConfig credentialConfig,
                                                        Map<String, List<String>> declaredSigningAlgsByCryptoSuite) {
        List<String> stored = credentialConfig.getCredentialSigningAlgValuesSupported();
        if (stored == null || stored.isEmpty()) {
            return deriveSigningAlgs(credentialConfig.getSignatureCryptoSuite(),
                    credentialConfig.getSignatureAlgo(), declaredSigningAlgsByCryptoSuite);
        }

        List<String> resolved = new ArrayList<>();
        for (String value : stored) {
            if (value == null) {
                continue;
            }
            List<String> algsForSuite = declaredSigningAlgsByCryptoSuite.get(value);
            if (algsForSuite != null) {
                resolved.addAll(algsForSuite);
            } else {
                resolved.add(value);
            }
        }
        return resolved.isEmpty()
                ? deriveSigningAlgs(credentialConfig.getSignatureCryptoSuite(),
                        credentialConfig.getSignatureAlgo(), declaredSigningAlgsByCryptoSuite)
                : resolved;
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
