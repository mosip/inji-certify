/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.spi.VCSigner;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.services.ldsigner.ProofSignatureStrategy;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

/**
 * KeymanagerLibSigner is a VCSigner which uses the Certify embedded
 * keymanager to perform VC signing tasks for JSON LD VCs.
 * These are the known external requirements:
 * - the public key must be pre-hosted for the VC & should be available
 *    so long that VC should be verifiable
 * - the VC should have a validFrom or issuanceDate in a specific UTC format
 */
@Slf4j
@Service
public class KeymanagerLibSigner implements VCSigner {

    @Autowired
    SignatureService signatureService;
    @Autowired
    ProofSignatureStrategy signProps;
    @Value("${mosip.certify.issuer.pub.key}")
    private String hostedKey;

    @Override
    public VCResult<JsonLDObject> perform(String templatedVC) {
        // Can the below lines be done at Templating side itself ?
        VCResult<JsonLDObject> VC = new VCResult<>();
        JsonLDObject j = JsonLDObject.fromJson(templatedVC);
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
        Map<String, String> props = signProps.getProperties();
        String signatureAlgorithm = props.get(KeyManagerConstants.VC_SIGN_ALGO);
        String keyAppId = props.get(KeyManagerConstants.KEY_APP_ID);
        String keyRefId = props.get(KeyManagerConstants.KEY_REF_ID);
        String keyManagerSignAlgo = props.get(KeyManagerConstants.KEYMGR_SIGN_ALGO);
        LdProof vcLdProof = LdProof.builder().defaultContexts(false).defaultTypes(false).type(signatureAlgorithm)
                .created(createDate).proofPurpose(VCDMConstants.ASSERTION_METHOD)
                .verificationMethod(URI.create(hostedKey))
                .build();
        // 1. Canonicalize
        Canonicalizer canonicalizer = signProps.getCanonicalizer();
        byte[] vcSignBytes = null;
        try {
            vcSignBytes = canonicalizer.canonicalize(vcLdProof, j);
        } catch (IOException | GeneralSecurityException | JsonLDException e) {
            log.error("Error during canonicalization", e.getMessage());
            throw new CertifyException("Error during canonicalization");
        }

        // 2. VC Sign
        String vcEncodedData = Base64.getUrlEncoder().encodeToString(vcSignBytes);
        JWSSignatureRequestDto payload = new JWSSignatureRequestDto();
        payload.setDataToSign(vcEncodedData);
        payload.setApplicationId(keyAppId);
        payload.setReferenceId(keyRefId); // alg, empty = RSA
        payload.setIncludePayload(false);
        payload.setIncludeCertificate(false);
        payload.setIncludeCertHash(true);
        payload.setValidateJson(false);
        payload.setB64JWSHeaderParam(false);
        payload.setCertificateUrl("");
        payload.setSignAlgorithm(keyManagerSignAlgo); // RSSignature2018 --> RS256, PS256, ES256
        // TODO: Should this be a well defined Certify Exception for better comms b/w Certify & Support team?
        JWTSignatureResponseDto jwsSignedData = signatureService.jwsSign(payload);
        String sign = jwsSignedData.getJwtSignedData();
        LdProof ldProofWithJWS = signProps.getProof(vcLdProof, sign) ;
        ldProofWithJWS.addToJsonLDObject(j);
        VC.setCredential(j);
        return VC;
        // TODO: Check if this is really a VC
        // MOSIP ref: https://github.com/mosip/id-authentication/blob/master/authentication/authentication-service/src/main/java/io/mosip/authentication/service/kyc/impl/VciServiceImpl.java#L281
    }
}
