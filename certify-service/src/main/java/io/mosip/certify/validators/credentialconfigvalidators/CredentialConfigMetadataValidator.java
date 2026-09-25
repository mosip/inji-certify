package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.Error;
import io.mosip.certify.utils.CredentialConfigMetadataResolver;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates the three per-configuration metadata attributes — cryptographic_binding_methods_supported,
 * credential_signing_alg_values_supported and proof_types_supported — against what the deployment
 * declares for them.
 * <p>
 * Every method appends to the caller's error list rather than throwing, so a single request reports
 * all of its problems at once instead of one per round trip. The declared values are passed in rather
 * than injected, keeping the class a pure function of request and configuration.
 */
public class CredentialConfigMetadataValidator {

    private CredentialConfigMetadataValidator() {
    }

    public static void validateBindingMethods(List<String> requested, String credentialFormat,
                                              Map<String, List<String>> declaredBindingMethodsByFormat,
                                              List<Error> errors) {
        if (requested.isEmpty()) {
            errors.add(buildError(ErrorConstants.INVALID_REQUEST,
                    "cryptographicBindingMethodsSupported was provided but is empty."));
            return;
        }

        List<String> declared = declaredBindingMethodsByFormat.get(credentialFormat);
        if (declared == null || declared.isEmpty()) {
            errors.add(buildError(ErrorConstants.CRYPTOGRAPHIC_BINDING_CONFIG_NOT_FOUND,
                    "No cryptographic binding methods are declared for the credential format: " + credentialFormat));
            return;
        }

        for (String bindingMethod : requested) {
            if (!declared.contains(bindingMethod)) {
                errors.add(buildError(ErrorConstants.UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD,
                        "The cryptographic binding method " + bindingMethod + " is not supported for the credential format "
                                + credentialFormat + ". The supported values are: " + declared));
            }
        }
    }

    public static void validateSigningAlgs(List<String> requested, String signatureCryptoSuite,
                                           Map<String, List<String>> declaredSigningAlgsByCryptoSuite,
                                           Map<String, List<List<String>>> keyAliasMapper,
                                           List<Error> errors) {
        if (requested.isEmpty()) {
            errors.add(buildError(ErrorConstants.INVALID_REQUEST,
                    "credentialSigningAlgValuesSupported was provided but is empty."));
            return;
        }

        if (signatureCryptoSuite == null) {
            // Formats such as dc+sd-jwt carry a signature algorithm rather than a crypto suite, so the
            // allow-list is the set of algorithms the deployment actually holds a signing key for.
            for (String signingAlg : requested) {
                if (!keyAliasMapper.containsKey(signingAlg)) {
                    errors.add(buildError(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                            "No signing key is available for the credential signing algorithm " + signingAlg
                                    + ". The supported values are: " + keyAliasMapper.keySet()));
                }
            }
            return;
        }

        List<String> declared = declaredSigningAlgsByCryptoSuite.get(signatureCryptoSuite);
        if (declared == null) {
            errors.add(buildError(ErrorConstants.UNSUPPORTED_CRYPTO_SUITE,
                    "Unsupported signature crypto suite: " + signatureCryptoSuite));
            return;
        }

        for (String signingAlg : requested) {
            if (!declared.contains(signingAlg)) {
                errors.add(buildError(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                        "The credential signing algorithm " + signingAlg + " is not supported for the crypto suite "
                                + signatureCryptoSuite + ". The supported values are: " + declared));
            }
        }
    }

    /**
     * An mso_mdoc credential is advertised with COSE algorithm identifiers, so an algorithm with no COSE
     * equivalent cannot be used for that format. This is the format's own constraint rather than the
     * deployment's, so it applies to the algorithms a request selects and equally to the ones derived
     * from configuration when the request selects none - both end up in the issuer metadata.
     */
    public static void validateCoseSigningAlgs(List<String> effective, String credentialFormat,
                                               Set<String> coseSigningAlgs, List<Error> errors) {
        if (!VCFormats.MSO_MDOC.equals(credentialFormat)) {
            return;
        }

        for (String signingAlg : effective) {
            if (!coseSigningAlgs.contains(signingAlg)) {
                errors.add(buildError(ErrorConstants.UNSUPPORTED_CREDENTIAL_SIGNING_ALG,
                        "The credential signing algorithm " + signingAlg + " is not supported for the credential format "
                                + VCFormats.MSO_MDOC + ". The supported values are: " + coseSigningAlgs));
            }
        }
    }

    public static void validateProofTypes(Map<String, Object> requested,
                                          Map<String, Object> declaredProofTypes,
                                          List<Error> errors) {
        if (requested.isEmpty()) {
            errors.add(buildError(ErrorConstants.INVALID_REQUEST, "proofTypesSupported was provided but is empty."));
            return;
        }

        for (Map.Entry<String, Object> entry : requested.entrySet()) {
            String proofType = entry.getKey();
            if (!declaredProofTypes.containsKey(proofType)) {
                errors.add(buildError(ErrorConstants.UNSUPPORTED_PROOF_TYPE,
                        "The proof type " + proofType + " is not supported. The supported values are: "
                                + declaredProofTypes.keySet()));
                continue;
            }
            validateProofTypeDetail(proofType, entry.getValue(), declaredProofTypes, errors);
        }
    }

    private static void validateProofTypeDetail(String proofType, Object detail,
                                                Map<String, Object> declaredProofTypes,
                                                List<Error> errors) {
        if (detail == null) {
            return;
        }
        if (!(detail instanceof Map)) {
            errors.add(buildError(ErrorConstants.INVALID_REQUEST,
                    "The proof type " + proofType + " must carry an object holding "
                            + Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED + "."));
            return;
        }

        Map<?, ?> requestedDetail = (Map<?, ?>) detail;
        for (Object attribute : requestedDetail.keySet()) {
            if (!Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED.equals(attribute)) {
                errors.add(buildError(ErrorConstants.INVALID_REQUEST,
                        "The attribute " + attribute + " is not recognised for the proof type " + proofType
                                + ". The only recognised attribute is " + Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED + "."));
            }
        }

        Object requestedAlgs = requestedDetail.get(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED);
        if (requestedAlgs == null) {
            return;
        }
        if (!(requestedAlgs instanceof List)) {
            errors.add(buildError(ErrorConstants.INVALID_REQUEST,
                    Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED + " for the proof type " + proofType + " must be a list."));
            return;
        }

        List<?> requestedAlgList = (List<?>) requestedAlgs;
        if (requestedAlgList.isEmpty()) {
            errors.add(buildError(ErrorConstants.INVALID_REQUEST,
                    Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED + " for the proof type " + proofType
                            + " was provided but is empty."));
            return;
        }

        List<String> declared = CredentialConfigMetadataResolver.declaredProofSigningAlgs(declaredProofTypes, proofType);
        for (Object proofSigningAlg : requestedAlgList) {
            if (!declared.contains(proofSigningAlg)) {
                errors.add(buildError(ErrorConstants.UNSUPPORTED_PROOF_SIGNING_ALG,
                        "The proof signing algorithm " + proofSigningAlg + " is not supported for the proof type "
                                + proofType + ". The supported values are: " + declared));
            }
        }
    }

    /**
     * A configuration without holder binding is not possible for mso_mdoc: ISO/IEC 18013-5 requires
     * deviceKeyInfo in the mobile security object.
     */
    public static void validateWithoutHolderBinding(String credentialFormat, List<Error> errors) {
        if (VCFormats.MSO_MDOC.equals(credentialFormat)) {
            errors.add(buildError(ErrorConstants.INVALID_REQUEST,
                    "mso_mdoc credentials are always holder-bound; cryptographicBindingMethodsSupported and proofTypesSupported must not be empty."));
        }
    }

    private static Error buildError(String errorCode, String errorMessage) {
        return new Error(errorCode, errorMessage);
    }
}
