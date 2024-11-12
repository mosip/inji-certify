package io.mosip.certify.services.ldsigner;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.services.KeyManagerConstants;
import io.mosip.kernel.signature.dto.SignRequestDtoV2;
import io.mosip.kernel.signature.dto.SignResponseDto;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Ed25519SignatureAlgorithm2020 as per
 *  https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/
 */
@Component
@ConditionalOnProperty(name = "mosip.certify.issuer.vc-sign-algo", havingValue = SignatureAlg.ED25519_SIGNATURE_SUITE_2020)
public class Ed25519ProofSignature2020 implements ProofSignatureStrategy {

    @Autowired
    SignatureServicev2 signatureService;

    Canonicalizer canonicalizer = new URDNA2015Canonicalizer();

    @Override
    public String getName() {
        return SignatureAlg.ED25519_SIGNATURE_SUITE_2020;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    @Override
    public String getProof(String vcEncodedHash) {
        SignRequestDtoV2 srd = new SignRequestDtoV2();
        srd.setApplicationId(KeyManagerConstants.CERTIFY_MOCK_ED25519);
        srd.setReferenceId(KeyManagerConstants.ED25519_REF_ID);
        srd.setDataToSign(vcEncodedHash);
        srd.setResponseEncodingFormat("base58btc");
        srd.setSignAlgorithm(JWSAlgorithm.EdDSA);
        SignResponseDto s = signatureService.signv2(srd);
        return s.getSignature();
    }

    @Override
    public LdProof buildProof(LdProof vcLdProof, String sign) {
        return LdProof.builder().base(vcLdProof).defaultContexts(false)
                .proofValue(sign).build();
    }
}
