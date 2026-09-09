/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.entity.CredentialConfig;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Reads what the deployment declares for cryptographic_binding_methods_supported,
 * credential_signing_alg_values_supported and proof_types_supported, and turns it into the values a
 * credential configuration stores and advertises.
 * <p>
 * This is the counterpart to CredentialConfigMetadataValidator: this class answers what the deployment
 * declares and what should be stored, the validator answers whether a requested value is among them.
 * The declared values are passed in rather than injected, so both remain pure functions of request and
 * configuration.
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
     * The algorithms declared for the crypto suite, rather than the crypto suite name itself, so that
     * what is persisted is an algorithm value such as EdDSA and not a suite such as Ed25519Signature2020.
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
     * Fills in proof_signing_alg_values_supported for a proof type named without one, so that what is
     * stored always carries the algorithms the deployment declares for that proof type.
     * <p>
     * Storing the bare proof type instead would publish it with no algorithms, which OpenID4VCI does not
     * allow, and JwtProofValidator reads a missing list as an empty one and rejects every proof, so the
     * configuration would silently stop issuing.
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
