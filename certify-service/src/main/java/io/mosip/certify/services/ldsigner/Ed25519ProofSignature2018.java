package io.mosip.certify.services.ldsigner;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.services.KeyManagerConstants;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Ed25519SignatureAlgorithm2018 as per https://w3c-ccg.github.io/lds-ed25519-2018/
 */
@Component
@ConditionalOnProperty(name = "mosip.certify.issuer.vc-sign-algo", havingValue = SignatureAlg.ED25519_SIGNATURE_SUITE)
public class Ed25519ProofSignature2018 implements ProofSignatureStrategy {
    @Autowired
    SignatureService signatureService;

    Canonicalizer canonicalizer = new URDNA2015Canonicalizer();

    @Override
    public String getName() {
        return SignatureAlg.ED25519_SIGNATURE_SUITE;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    @Override
    public String getProof(String vcEncodedHash) {
        JWSSignatureRequestDto payload = new JWSSignatureRequestDto();
        payload.setDataToSign(vcEncodedHash);
        payload.setApplicationId(KeyManagerConstants.CERTIFY_MOCK_ED25519);
        payload.setReferenceId(KeyManagerConstants.ED25519_REF_ID); // alg, empty = RSA
        payload.setIncludePayload(false);
        payload.setIncludeCertificate(false);
        payload.setIncludeCertHash(true);
        payload.setValidateJson(false);
        payload.setB64JWSHeaderParam(false);
        payload.setCertificateUrl("");
        payload.setSignAlgorithm(JWSAlgorithm.EdDSA); // RSSignature2018 --> RS256, PS256, ES256
        JWTSignatureResponseDto jwsSignedData = signatureService.jwsSign(payload);
        return jwsSignedData.getJwtSignedData();
    }

    @Override
    public LdProof buildProof(LdProof vcLdProof, String sign) {
        return LdProof.builder().base(vcLdProof).defaultContexts(false)
                .jws(sign).build();
    }
}
