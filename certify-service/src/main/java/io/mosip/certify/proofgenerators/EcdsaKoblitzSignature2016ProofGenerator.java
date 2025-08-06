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
 * EcdsaKoblitzSignature2016 as per https://w3c-ccg.github.io/lds-koblitz2016/
 * - secp256k1
 * - used by Bitcoin & Etherium
 * - from W3C Web Payments Community Group
 *
 * // NOTE: Avoid using this signature and use the 2019 EC K1 instead.
 */
@Component
public class EcdsaKoblitzSignature2016ProofGenerator implements ProofGenerator {

    @Autowired
    SignatureService signatureService;

    Canonicalizer canonicalizer = new URDNA2015Canonicalizer();

    @Override
    public String getName() {
        return SignatureAlg.EC_K1_2016;
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