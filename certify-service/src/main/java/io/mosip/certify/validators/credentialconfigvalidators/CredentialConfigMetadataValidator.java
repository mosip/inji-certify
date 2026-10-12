package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.Error;
import io.mosip.certify.utils.CredentialConfigMetadataResolver;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates the three per-configuration metadata attributes — cryptographic_binding_methods_supported,
 * credential_signing_alg_values_supported and proof_types_supported — against what the deployment
 * declares for them.
 * <p>
 * All three are mandatory: a request that leaves one out, sends it as null or sends it empty is
 * rejected, and nothing is filled in from the deployment configuration, which is the allow-list only.
 * <p>
 * Every method appends to the caller's error list rather than throwing, so a single request reports
 * all of its problems at once instead of one per round trip. The declared values are passed in rather
 * than injected, keeping the class a pure function of request and configuration.
 */
public class CredentialConfigMetadataValidator {

    private static final String BINDING_METHODS_ATTRIBUTE = "cryptographicBindingMethodsSupported";
    private static final String SIGNING_ALGS_ATTRIBUTE = "credentialSigningAlgValuesSupported";
    private static final String PROOF_TYPES_ATTRIBUTE = "proofTypesSupported";

    private CredentialConfigMetadataValidator() {
    }

    public static void validateBindingMethods(List<String> requested, String credentialFormat,
                                              Map<String, List<String>> declaredBindingMethodsByFormat,
                                              List<Error> errors) {
        if (rejectMissing(requested, BINDING_METHODS_ATTRIBUTE, errors)
                || rejectEmptyBindingOrProofTypes(requested, BINDING_METHODS_ATTRIBUTE, errors)) {
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
        if (rejectMissing(requested, SIGNING_ALGS_ATTRIBUTE, errors)) {
            return;
        }
        // A credential cannot be issued without a signing algorithm, so unlike the binding methods and
        // proof types this attribute can never be empty.
        if (requested.isEmpty()) {
            errors.add(missingOrEmptyError(SIGNING_ALGS_ATTRIBUTE));
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
     * deployment's, so it applies even to an algorithm the deployment declares for the crypto suite.
     */
    public static void validateCoseSigningAlgs(List<String> requested, String credentialFormat,
                                               Set<String> coseSigningAlgs, List<Error> errors) {
        if (!VCFormats.MSO_MDOC.equals(credentialFormat) || requested == null) {
            return;
        }

        for (String signingAlg : requested) {
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
        if (rejectMissing(requested, PROOF_TYPES_ATTRIBUTE, errors)
                || rejectEmptyBindingOrProofTypes(requested, PROOF_TYPES_ATTRIBUTE, errors)) {
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

        // A proof type is advertised with the algorithms it accepts, and none are filled in from the
        // deployment configuration, so the request has to name them.
        Object requestedAlgs = requestedDetail.get(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED);
        String algsAttribute = Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED + " for the proof type " + proofType;
        if (requestedAlgs == null || requestedAlgs instanceof List<?> algs && algs.isEmpty()) {
            errors.add(missingOrEmptyError(algsAttribute));
            return;
        }
        if (!(requestedAlgs instanceof List<?> requestedAlgList)) {
            errors.add(buildError(ErrorConstants.INVALID_REQUEST, algsAttribute + " must be a list."));
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
     * A missing attribute and one sent as null are the same to Jackson, and both are rejected.
     */
    private static boolean rejectMissing(Object requested, String attribute, List<Error> errors) {
        if (requested != null) {
            return false;
        }
        errors.add(missingOrEmptyError(attribute));
        return true;
    }

    /**
     * An empty {@code cryptographicBindingMethodsSupported} or {@code proofTypesSupported} is currently
     * rejected. This check is temporary and is removed once an empty value is given a meaning.
     */
    private static boolean rejectEmptyBindingOrProofTypes(Object requested, String attribute, List<Error> errors) {
        boolean empty = requested instanceof Collection<?> values ? values.isEmpty() : ((Map<?, ?>) requested).isEmpty();
        if (!empty) {
            return false;
        }
        errors.add(missingOrEmptyError(attribute));
        return true;
    }

    /**
     * A missing value and an empty one are rejected the same way, with the same message.
     */
    private static Error missingOrEmptyError(String attribute) {
        return buildError(ErrorConstants.INVALID_REQUEST, attribute + " is mandatory and must not be empty.");
    }

    private static Error buildError(String errorCode, String errorMessage) {
        return new Error(errorCode, errorMessage);
    }
}
