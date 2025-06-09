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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.signer.LdSigner;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.proofgenerators.dip.KeymanagerByteSigner;
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
    public static final Map<String, String> cryptoSuiteCanonicalizerMap = Map.of(
            SignatureAlg.EC_JCS_2019, "jcs",
            SignatureAlg.EC_RDFC_2019, "urdna2015" // this is the canonicalizer name used by DanubeTech
    );
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
            Canonicalizer canonicalizer = proofGenerator.getCanonicalizer();
            byte[] vcHashBytes;
            try {
                vcHashBytes = canonicalizer.canonicalize(vcLdProof, j);
            } catch (IOException | GeneralSecurityException | JsonLDException e) {
                log.error("Error during canonicalization", e.getMessage());
                throw new CertifyException("Error during canonicalization");
            }
            String vcEncodedHash = Base64.getUrlEncoder().encodeToString(vcHashBytes);
            LdProof ldProofWithJWS = proofGenerator.generateProof(vcLdProof, vcEncodedHash, keyReferenceDetails);
            ldProofWithJWS.addToJsonLDObject(j);
        } else {
            DataIntegrityProof d = DataIntegrityProof.builder()
                    .created(createDate)
                    .proofPurpose(VCDMConstants.ASSERTION_METHOD)
                    .cryptosuite(dataIntegrityCryptoSuite)
                    .verificationMethod(URI.create(publicKeyURL))
                    .type(SignatureAlg.DATA_INTEGRITY).build();
            // Canonicalize the DI VC
            // assume that DataIntegrityProof cryptoSuite always has a '-' in the name
            com.danubetech.dataintegrity.canonicalizer.Canonicalizer c =
                    com.danubetech.dataintegrity.canonicalizer.Canonicalizers
                            .findDefaultCanonicalizerByAlgorithm(cryptoSuiteCanonicalizerMap.get(dataIntegrityCryptoSuite));
            byte cano[];
            try {
                cano = c.canonicalize(d, j);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            } catch (JsonLDException e) {
                throw new RuntimeException(e);
            }
            // Call KeymanagerByteSigner to sign the data with d
            KeymanagerByteSigner k = new KeymanagerByteSigner(dataIntegrityCryptoSuite, appID, refID,
                    signatureService);
            try {
                // TODO: replace null with the actual canonicalized byte input
                byte[] output = k.sign(cano, dataIntegrityCryptoSuite); // already multibase bas58btc
                String s = new String(output, StandardCharsets.UTF_8);
                d.setJsonObjectKeyValue("proofValue", s);
                // TODO: check source and destination of the JSONLD Object addition
                d.addToJsonLDObject(j);
                // convert the byte array to a string
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
            // add to the VC(j)
        }
        VC.setCredential(j);
        VC.setFormat("ldp_vc");
        return VC;
    }

}