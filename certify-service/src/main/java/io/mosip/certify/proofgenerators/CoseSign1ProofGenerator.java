package io.mosip.certify.proofgenerators;

import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * COSE_Sign1 ProofGenerator for mDoc (ISO 18013-5) Mobile Security Objects
 * This generates COSE signatures for CBOR-encoded payloads used in mobile documents.
 */
@Slf4j
@Component
public class CoseSign1ProofGenerator implements ProofGenerator {

    @Autowired
    private CoseSignatureService coseSignatureService;

    @Override
    public String getName() {
        return SignatureAlg.COSE_SIGN1;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        // COSE uses CBOR encoding, not JSON-LD canonicalization
        // Return null or a no-op canonicalizer since CBOR is already canonical
        return null;
    }

    /**
     * Generates COSE_Sign1 signature for the given payload (typically MSO CBOR bytes)
     *
     * @param vcLdProof not used for COSE (kept for interface compatibility)
     * @param payloadData Base64URL-encoded CBOR payload to sign
     * @param keyID map containing applicationId and referenceId
     * @return LdProof with COSE signature (not applicable, returns null)
     */
    @Override
    public LdProof generateProof(LdProof vcLdProof, String payloadData, Map<String, String> keyID) {
        // This method signature doesn't fit COSE well since LdProof is for JSON-LD
        // Consider creating a specialized method instead
        throw new UnsupportedOperationException(
                "Use generateCoseSignature() method for COSE signing instead"
        );
    }

    /**
     * Generates COSE_Sign1 signature for mDoc MSO
     *
     * @param cborPayload the CBOR-encoded MSO bytes
     * @param applicationId the application ID for key lookup
     * @param referenceId the reference ID for key lookup
     * @param signAlgorithm the signature algorithm (e.g., "ES256")
     * @param includeX5c whether to include x5c certificate chain in protected header
     * @return COSE_Sign1 signature as byte array
     * @throws CertifyException if signing fails
     */
    public byte[] generateCoseSignature(
            byte[] cborPayload,
            String applicationId,
            String referenceId,
            String signAlgorithm,
            boolean includeX5c) throws CertifyException {

        try {
            // Convert payload to Base64URL
            String base64UrlPayload = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(cborPayload);

            // Build COSE sign request
            CoseSignRequestDto signRequest = new CoseSignRequestDto();
            signRequest.setPayload(base64UrlPayload);
            signRequest.setApplicationId(applicationId);
            signRequest.setReferenceId(referenceId);
            signRequest.setAlgorithm(signAlgorithm);

            // Configure protected header
            Map<String, Object> protectedHeader = new HashMap<>();
            if (includeX5c) {
                protectedHeader.put("x5c", true);
            }
            signRequest.setProtectedHeader(protectedHeader);

            // Perform COSE signing
            String hexSignedData = coseSignatureService.coseSign1(signRequest).getSignedData();

            // Convert hex string to bytes
            return hexStringToByteArray(hexSignedData);

        } catch (CertifyException e) {
            log.error("COSE signing failed: {}", e.getMessage(), e);
            throw new CertifyException("COSE_Sign1 generation failed: " + e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error during COSE signing: {}", e.getMessage(), e);
            throw new CertifyException("COSE_Sign1 generation failed: " + e.getMessage());
        }
    }

    /**
     * Convenience method matching the original signMSO signature
     */
    public byte[] signMSO(
            byte[] msoCbor,
            String applicationId,
            String referenceId,
            String signAlgorithm) throws CertifyException {

        return generateCoseSignature(msoCbor, applicationId, referenceId, signAlgorithm, true);
    }

    /**
     * Converts hex string to byte array
     */
    private byte[] hexStringToByteArray(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
                    + Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }
}