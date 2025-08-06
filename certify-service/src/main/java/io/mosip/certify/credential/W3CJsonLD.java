/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.signer.LdSigner;
import com.danubetech.dataintegrity.signer.LdSignerRegistry;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.proofgenerators.ProofGeneratorFactory;
import io.mosip.certify.proofgenerators.dataintegrity.KeymanagerByteSigner;
import io.mosip.certify.proofgenerators.dataintegrity.KeymanagerByteSignerFactory;
import io.mosip.certify.services.CertifyIssuanceServiceImpl;
import io.mosip.certify.utils.CredentialUtils;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.proofgenerators.ProofGenerator;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
public class W3CJsonLD extends Credential{
    @Autowired
    ProofGeneratorFactory proofGeneratorFactory;
    @Autowired
    SignatureServicev2 signatureService;
    @Autowired
    DIDDocumentUtil didDocumentUtil;


    /**
     * Constructor for credentials
     *
     * @param vcFormatter
     * @param signatureService
     */
    public W3CJsonLD(VCFormatter vcFormatter, SignatureService signatureService) {
        super(vcFormatter, signatureService);
    }


    @Override
    public boolean canHandle(String format){
        if(format.equals("ldp_vc")){
            return true;
        }
        return false;
    }

    /**
     * Adds a signature/proof. Based on the actual implementation the input
     * could be different, its recommended that the input matches the output
     * of the respective createCredential, for eg: Base64, Sringified JSON etc.
     * <p>In the defaulat abstract implementation we assume
     * ```Base64.getUrlEncoder().encodeToString(vcToSign)``` </p>
     * @param vcToSign actual vc as returned by the `createCredential` method.
     * @param headers headers to be added. Can be null.
     */
    @Override
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm, String appID, String refID, String didUrl, String signatureCryptoSuite){
        VCResult<JsonLDObject> vcResult = new VCResult<>();
        Map<String,String> keyReferenceDetails = Map.of(Constants.APPLICATION_ID, appID, Constants.REFERENCE_ID, refID);
        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcToSign);
        jsonLDObject.setDocumentLoader(null);
        // NOTE: other aspects can be configured via keyMgrInput map
        String validFrom;
        if (jsonLDObject.getJsonObject().containsKey(VCDM1Constants.ISSUANCE_DATE)) {
            validFrom = jsonLDObject.getJsonObject().get(VCDM1Constants.ISSUANCE_DATE).toString();
        } else if (jsonLDObject.getJsonObject().containsKey(VCDM2Constants.VALID_FROM)){
            validFrom = jsonLDObject.getJsonObject().get(VCDM2Constants.VALID_FROM).toString();
        } else {
            validFrom = ZonedDateTime.now(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        }
        // TODO: VC Data Model spec doesn't specify a single date format or a
        //  timezone restriction, this will have to be supported timely.
        Date createDate = Date
                .from(LocalDateTime
                        .parse(validFrom,
                                DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN))
                        .atZone(ZoneId.systemDefault()).toInstant());

        CertificateResponseDTO certificateResponseDTO = didDocumentUtil.getCertificateDataResponseDto(appID, refID);
        String kid = certificateResponseDTO.getKeyId();
        if (CertifyIssuanceServiceImpl.keyChooser.containsKey(signatureCryptoSuite)) {
            // legacy signature algos such as Ed25519Signature{2018,2020}
            ProofGenerator proofGenerator = proofGeneratorFactory.getProofGenerator(signatureCryptoSuite)
                    .orElseThrow(() ->
                            new CertifyException("Proof generator not found for algorithm: " + signatureCryptoSuite));
            LdProof vcLdProof = LdProof.builder().defaultContexts(false).defaultTypes(false).type(proofGenerator.getName())
                    .created(createDate).proofPurpose(VCDMConstants.ASSERTION_METHOD)
                    .verificationMethod(URI.create(didUrl + "#" + kid))
                    .build();
            LdProof ldProofWithJWS = CredentialUtils.generateLdProof(vcLdProof, jsonLDObject,
                    keyReferenceDetails, proofGenerator);
            ldProofWithJWS.addToJsonLDObject(jsonLDObject);
        } else {
            LdSigner signer = LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(SignatureAlg.DATA_INTEGRITY);
            KeymanagerByteSigner keymanagerByteSigner = KeymanagerByteSignerFactory.getInstance(appID, refID, signatureService, signAlgorithm);
            signer.setSigner(keymanagerByteSigner);
            signer.setCryptosuite(signatureCryptoSuite);

            DataIntegrityProof dataIntegrityProof = DataIntegrityProof.builder()
                    .created(createDate)
                    .proofPurpose(VCDMConstants.ASSERTION_METHOD)
                    .cryptosuite(signatureCryptoSuite)
                    .verificationMethod(URI.create(didUrl + "#" + kid))
                    .type(SignatureAlg.DATA_INTEGRITY).build();

            dataIntegrityProof = CredentialUtils.generateDataIntegrityProof(dataIntegrityProof, jsonLDObject, signer);
            dataIntegrityProof.addToJsonLDObject(jsonLDObject);
        }
        vcResult.setCredential(jsonLDObject);
        vcResult.setFormat("ldp_vc");
        return vcResult;
    }

}