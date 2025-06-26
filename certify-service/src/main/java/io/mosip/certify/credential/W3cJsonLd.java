/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.signer.LdSigner;
import com.danubetech.dataintegrity.signer.LdSignerRegistry;
import foundation.identity.jsonld.JsonLDUtils;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.proofgenerators.dip.KeymanagerByteSigner;
import io.mosip.certify.proofgenerators.dip.KeymanagerByteSignerFactory;
import io.mosip.certify.utils.CredentialUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.proofgenerators.ProofGenerator;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
public class W3cJsonLd extends Credential{
    //TODO: This has to move to a factory
    @Autowired
    ProofGenerator proofGenerator;
    @Autowired
    SignatureServicev2 signatureService;
    @Value("${mosip.certify.data-provider-plugin.data-integrity.crypto-suite:}")
    private String dataIntegrityCryptoSuite;

    /**
     * Constructor for credentials
     *
     * @param vcFormatter
     * @param signatureService
     */
    public W3cJsonLd(VCFormatter vcFormatter, SignatureService signatureService) {
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
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm, String appID, String refID, String publicKeyURL){
        VCResult<JsonLDObject> VC = new VCResult<>();
//        signAlgorithm = "ecdsa-rdfc-2019"; // TODO: this should be configurable
        Map<String,String> keyReferenceDetails = Map.of(Constants.APPLICATION_ID, appID, Constants.REFERENCE_ID, refID);
        JsonLDObject j = JsonLDObject.fromJson(vcToSign);
        j.setDocumentLoader(null);
        // NOTE: other aspects can be configured via keyMgrInput map
        String validFrom;
        if (j.getJsonObject().containsKey(VCDM1Constants.ISSUANCE_DATE)) {
            validFrom = j.getJsonObject().get(VCDM1Constants.ISSUANCE_DATE).toString();
        } else if (j.getJsonObject().containsKey(VCDM2Constants.VALID_FROM)){
            validFrom = j.getJsonObject().get(VCDM2Constants.VALID_FROM).toString();
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
        if (dataIntegrityCryptoSuite.isEmpty()) {
            // legacy signature algos such as Ed25519Signature{2018,2020}
            LdProof vcLdProof = LdProof.builder().defaultContexts(false).defaultTypes(false).type(proofGenerator.getName())
                    .created(createDate).proofPurpose(VCDMConstants.ASSERTION_METHOD)
                    .verificationMethod(URI.create(publicKeyURL))
                    .build();
            LdProof ldProofWithJWS = CredentialUtils.generateLdProof(vcLdProof, j,
                    keyReferenceDetails, proofGenerator);
            ldProofWithJWS.addToJsonLDObject(j);
        } else {
            LdSigner signer = LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(SignatureAlg.DATA_INTEGRITY);
            KeymanagerByteSigner keymanagerByteSigner = KeymanagerByteSignerFactory.getInstance(appID, refID, signatureService, signAlgorithm);
            signer.setSigner(keymanagerByteSigner);
            signer.setCryptosuite(dataIntegrityCryptoSuite);

            DataIntegrityProof dataIntegrityProof = DataIntegrityProof.builder()
                    .created(createDate)
                    .proofPurpose(VCDMConstants.ASSERTION_METHOD)
                    .cryptosuite(dataIntegrityCryptoSuite)
                    .verificationMethod(URI.create(publicKeyURL))
                    .type(SignatureAlg.DATA_INTEGRITY).build();

            dataIntegrityProof = CredentialUtils.generateDataIntegrityProof(dataIntegrityProof, j, signer);
            dataIntegrityProof.addToJsonLDObject(j);
        }
        VC.setCredential(j);
        VC.setFormat("ldp_vc");
        return VC;
    }

}