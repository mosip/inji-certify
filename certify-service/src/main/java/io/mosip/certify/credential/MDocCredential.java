/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.util.*;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.MDocUtils;
import io.mosip.kernel.signature.service.CoseSignatureService;
import io.mosip.kernel.signature.service.SignatureServicev2;
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
    SignatureServicev2 signatureService;

    @Autowired
    CoseSignatureService coseSignatureService;

    @Autowired
    DIDDocumentUtil didDocumentUtil;

    @Autowired
    private ObjectMapper objectMapper;

    public MDocCredential(VCFormatter vcFormatter, SignatureService signatureService) {
        super(vcFormatter, signatureService);
    }

    @Override
    public boolean canHandle(String format) {
        return Constants.MSO_MDOC_FORMAT.equals(format);
    }

    @Override
    public String createCredential(Map<String, Object> templateParams, String templateName) {
        try {
            String templatedJSON = super.createCredential(templateParams, templateName);
            log.info("Templated JSON: {}", templatedJSON);

            Map<String, Object> finalMDoc = MDocUtils.processTemplatedJson(templatedJSON, templateParams);

            // Convert to JSON and return
            String result = objectMapper.writeValueAsString(finalMDoc);
            log.info("Final mDoc credential created: {}", result);
            return result;

        } catch (Exception e) {
            log.error("Error creating mDoc credential: {}", e.getMessage(), e);
            throw new CertifyException("MDOC_CREATION_FAILED", "Failed to create mDoc credential", e);
        }
    }

    @Override
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm,
                                String appID, String refID, String didUrl, String signatureCryptoSuite) {
        try {
            log.info("Starting mDoc proof generation for appID: {}, refID: {}", appID, refID);

            VCResult<String> vcResult = new VCResult<>();

            // Parse the input mDoc JSON
            Map<String, Object> mDocJson = objectMapper.readValue(vcToSign, Map.class);
            log.info("Parsed mDoc JSON: {}", mDocJson);

            // Step 1: Generate random salts
            Map<String, Object> saltedNamespaces = MDocUtils.addRandomSalts(mDocJson);

            // Step 2: Calculate digests
            Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
            Map<String, Object> taggedNamespaces = MDocUtils.calculateDigests(saltedNamespaces, namespaceDigests);

            // Step 3: Create Mobile Security Object (MSO)
            Map<String, Object> mso = MDocUtils.createMobileSecurityObject(mDocJson, namespaceDigests, appID, refID);
            log.info("Created MSO: {}", mso);

            // Step 4: Sign MSO
            byte[] signedMSO = MDocUtils.signMSO(mso, appID, refID, signAlgorithm, didDocumentUtil, coseSignatureService);

            // Step 5: Create final IssuerSigned structure
            Map<String, Object> issuerSigned = MDocUtils.createIssuerSignedStructure(taggedNamespaces, signedMSO);

            // Step 7: Encode entire structure to CBOR
            byte[] cborIssuerSigned = MDocUtils.encodeToCBOR(issuerSigned);

            // Step 8: Base64url encode for transport
            String base64UrlCredential = Base64.getUrlEncoder().withoutPadding().encodeToString(cborIssuerSigned);

            // Step 9: Set result
            vcResult.setCredential(base64UrlCredential);
            vcResult.setFormat(Constants.MSO_MDOC_FORMAT);

            log.info("mDoc proof generation completed successfully");
            return vcResult;

        } catch (Exception e) {
            log.error("Error adding proof to mDoc: {}", e.getMessage(), e);
            throw new CertifyException("Failed to add proof to mDoc: " + e.getMessage());
        }
    }
}