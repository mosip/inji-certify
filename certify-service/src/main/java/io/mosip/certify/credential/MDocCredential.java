/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.util.*;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.MDocUtils;
import io.mosip.kernel.signature.service.CoseSignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import io.mosip.certify.utils.DIDDocumentUtil;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;

/**
 * MDocCredential implementation for ISO 18013-5 compliant mobile documents
 * Handles mDoc structure creation, namespace processing, and COSE signing
 */
@Slf4j
@Component
public class MDocCredential extends Credential {

    @Autowired
    CoseSignatureService coseSignatureService;

    @Autowired
    DIDDocumentUtil didDocumentUtil;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MDocUtils mDocUtils;

    public MDocCredential(VCFormatter vcFormatter, SignatureService signatureService) {
        super(vcFormatter, signatureService);
    }

    @Override
    public boolean canHandle(String format) {
        return VCFormats.MSO_MDOC.equals(format);
    }

    @Override
    public String createCredential(Map<String, Object> templateParams, String templateName) {
        try {
            String templatedJSON = super.createCredential(templateParams, templateName);
            Map<String, Object> finalMDoc = mDocUtils.processTemplatedJson(templatedJSON, templateParams);
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
            Map<String, Object> saltedNamespaces = MDocUtils.addRandomSalts(mDocJson);
            Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
            Map<String, Object> taggedNamespaces = MDocUtils.calculateDigests(saltedNamespaces, namespaceDigests);

            // Create Mobile Security Object (MSO)
            Map<String, Object> mso = MDocUtils.createMobileSecurityObject(mDocJson, namespaceDigests, appID, refID);
            byte[] signedMSO = MDocUtils.signMSO(mso, appID, refID, signAlgorithm, didDocumentUtil, coseSignatureService);
            Map<String, Object> issuerSigned = MDocUtils.createIssuerSignedStructure(taggedNamespaces, signedMSO);

            // Encode to CBOR, then to Base64
            byte[] cborIssuerSigned = MDocUtils.encodeToCBOR(issuerSigned);
            String base64UrlCredential = Base64.getUrlEncoder().withoutPadding().encodeToString(cborIssuerSigned);

            vcResult.setCredential(base64UrlCredential);
            vcResult.setFormat(VCFormats.MSO_MDOC);

            log.info("mDoc proof generation completed successfully");
            return vcResult;

        } catch (Exception e) {
            log.error("Error adding proof to mDoc: {}", e.getMessage(), e);
            throw new CertifyException("Failed to add proof to mDoc: " + e.getMessage());
        }
    }
}