package io.mosip.certify.services;

import com.apicatalog.jsonld.JsonLd;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.spi.VCSigner;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class KeymanagerLibSigner implements VCSigner {

    @Autowired
    SignatureService signatureService;
    @Override
    public VCResult<JsonLDObject> perform(String templatedVC, Map<String, String> keyMgrInput) {
        // TODO: Can the below lines be done at Templating side itself? Ask Hitesh.
        VCResult<JsonLDObject> VC = null;
        JsonLDObject j = JsonLDObject.fromJson(templatedVC);
        j.setDocumentLoader(null);
        Date validFrom = Date
                .from(LocalDateTime
                        .parse((String) j.getJsonObject().get(VCDM2Constants.VALID_FROM),
                                DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN))
                        .atZone(ZoneId.systemDefault()).toInstant());
        LdProof vcLdProof = LdProof.builder().defaultContexts(false).defaultTypes(false).type(SignatureAlg.RSA_SIGNATURE_2018)
                .created(validFrom).proofPurpose(VCDM2Constants.ASSERTION_METHOD)
                .verificationMethod(URI.create("https://vharsh.github.io/DID/mock-public-key.json"))
                // ^^ Why is this pointing to JWKS URL of eSignet??
                .build();
        // 1. Canonicalize
        URDNA2015Canonicalizer canonicalizer = new URDNA2015Canonicalizer();
        // VC Sign
        byte[] vcSignBytes = null;
        try {
            vcSignBytes = canonicalizer.canonicalize(vcLdProof, j);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (JsonLDException e) {
            throw new RuntimeException(e);
        }
        String vcEncodedData = Base64.getUrlEncoder().encodeToString(vcSignBytes);
        JWSSignatureRequestDto payload = new JWSSignatureRequestDto();
        // TODO: Set the alg
        payload.setDataToSign(vcEncodedData);
        payload.setApplicationId(""); // set the key name
        payload.setReferenceId(""); // alg
        payload.setIncludePayload(false);
        payload.setIncludeCertificate(false);
        payload.setIncludeCertHash(true);
        payload.setValidateJson(false);
        payload.setB64JWSHeaderParam(false);
        payload.setCertificateUrl("");
        payload.setSignAlgorithm("RS256"); // RSSignature2018 --> RS256, PS256, ES256
        JWTSignatureResponseDto jwsSignedData = signatureService.jwsSign(payload);
        String sign = jwsSignedData.getJwtSignedData();
        LdProof ldProofWithJWS = LdProof.builder().base(vcLdProof).defaultContexts(false)
                .jws(sign).build();
        ldProofWithJWS.addToJsonLDObject(j);
        VC.setCredential(j);
        return VC;
        // TODO: Check if this is really a VC
        // MOSIP ref: https://github.com/mosip/id-authentication/blob/master/authentication/authentication-service/src/main/java/io/mosip/authentication/service/kyc/impl/VciServiceImpl.java#L281
    }
}
