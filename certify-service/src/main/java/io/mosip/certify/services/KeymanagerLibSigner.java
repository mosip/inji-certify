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
 * - the VC should have a validFrom or issuanceDate in a specific UTC format,
 *  if missing it uses current time for proof creation timestamp.
 */
@Slf4j
@Service
public class KeymanagerLibSigner implements VCSigner {

    @Autowired
    ProofSignatureStrategy signProps;
    @Value("${mosip.certify.data-provider-plugin.issuer-public-key-uri}")
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
        LdProof vcLdProof = LdProof.builder().defaultContexts(false).defaultTypes(false).type(signProps.getName())
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
        String vcEncodedHash = Base64.getUrlEncoder().encodeToString(vcSignBytes);
        String sign = signProps.getProof(vcEncodedHash);
        LdProof ldProofWithJWS = signProps.buildProof(vcLdProof, sign);
        ldProofWithJWS.addToJsonLDObject(j);
        VC.setCredential(j);
        return VC;
        // MOSIP ref: https://github.com/mosip/id-authentication/blob/master/authentication/authentication-service/src/main/java/io/mosip/authentication/service/kyc/impl/VciServiceImpl.java#L281
    }
}
