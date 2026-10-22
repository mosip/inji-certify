package io.mosip.certify.credential;

import java.util.*;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.MDocProcessor;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.service.CoseSignatureService;
import lombok.extern.slf4j.Slf4j;

/**
 * MDocCredential implementation for ISO 18013-5 compliant mobile documents
 * Handles mDoc structure creation, namespace processing, and COSE signing
 */
@Slf4j
@Component
public class MDocCredential extends Credential {

    private final ObjectMapper objectMapper;

    private final MDocProcessor mDocProcessor;

    public MDocCredential(VCFormatter vcFormatter, SignatureService signatureService,
                          CoseSignatureService coseSignatureService, ObjectMapper objectMapper,
                          MDocProcessor mDocProcessor) {
        super(vcFormatter, signatureService, coseSignatureService);
        this.objectMapper = objectMapper;
        this.mDocProcessor = mDocProcessor;
    }

    @Override
    public boolean canHandle(String format) {
        return VCFormats.MSO_MDOC.equals(format);
    }

    @Override
    public String createCredential(Map<String, Object> updatedTemplateParams, String templateName) {
        try {
            String templatedJSON = super.createCredential(updatedTemplateParams, templateName);
            Map<String, Object> finalMDoc = mDocProcessor.processTemplatedJson(templatedJSON, updatedTemplateParams);
            return objectMapper.writeValueAsString(finalMDoc);

        } catch (Exception e) {
            log.error("Error creating mDoc credential: {}", e.getMessage(), e);
            throw new CertifyException("MDOC_CREATION_FAILED", "Failed to create mDoc credential", e);
        }
    }

    @Override
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm, String appID, String refID, String didUrl, String signatureCryptoSuite) {
        try {
            VCResult<String> vcResult = new VCResult<>();

            // Parse the input mDoc JSON
            Map<String, Object> mDocJson = objectMapper.readValue(vcToSign, Map.class);
            Map<String, Object> saltedNamespaces = MDocProcessor.addRandomSalts(mDocJson);
            Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
            Map<String, Object> taggedNamespaces = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

            // Create Mobile Security Object (MSO)
            Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, namespaceDigests);
            byte[] signedMSO = mDocProcessor.signMSO(mso, appID, refID, signAlgorithm);
            Map<String, Object> issuerSigned = MDocProcessor.createIssuerSignedStructure(taggedNamespaces, signedMSO);

            // Encode to CBOR, then to Base64
            byte[] cborIssuerSigned = MDocProcessor.encodeToCBOR(issuerSigned);
            String base64UrlCredential = Base64.getUrlEncoder().withoutPadding().encodeToString(cborIssuerSigned);

            vcResult.setCredential(base64UrlCredential);
            vcResult.setFormat(VCFormats.MSO_MDOC);
            return vcResult;

        } catch (Exception e) {
            log.error("Error adding proof to mDoc: {}", e.getMessage(), e);
            throw new CertifyException("MDOC_PROOF_FAILED", "Failed to add proof to mDoc", e);
        }
    }
}