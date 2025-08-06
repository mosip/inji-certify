package io.mosip.certify.proofgenerators;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * EcdsaSecp256k1Signature2019 as per https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/
 * - secp256k1
 * - from W3C Web Payments Community Group
 * - ref: https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1signature2019
 */
@Component
public class EcdsaSecp256k1Signature2019ProofGenerator implements ProofGenerator {

    @Autowired
    SignatureService signatureService;

    Canonicalizer canonicalizer = new URDNA2015Canonicalizer();

    @Override
    public String getName() {
        return SignatureAlg.EC_SECP256K1_2019;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    @Override
    public LdProof generateProof(LdProof vcLdProof, String vcEncodedHash, Map<String, String> keyID) {
        JWSSignatureRequestDto payload = new JWSSignatureRequestDto();
        payload.setDataToSign(vcEncodedHash);
        payload.setApplicationId(keyID.get(Constants.APPLICATION_ID));
        payload.setReferenceId(keyID.get(Constants.REFERENCE_ID));
        payload.setIncludePayload(false);
        payload.setIncludeCertificate(false);
        payload.setIncludeCertHash(true);
        payload.setValidateJson(false);
        payload.setB64JWSHeaderParam(false);
        payload.setCertificateUrl("");
        payload.setSignAlgorithm(JWSAlgorithm.ES256K);
        JWTSignatureResponseDto jwsSignedData = signatureService.jwsSign(payload);
        return LdProof.builder().base(vcLdProof).defaultContexts(false)
                .jws(jwsSignedData.getJwtSignedData()).build();
    }
}
