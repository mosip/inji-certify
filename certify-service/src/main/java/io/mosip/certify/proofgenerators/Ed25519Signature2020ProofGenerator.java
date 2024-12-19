package io.mosip.certify.proofgenerators;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.kernel.signature.dto.SignRequestDtoV2;
import io.mosip.kernel.signature.dto.SignResponseDto;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Ed25519SignatureAlgorithm2020 as per
 *  https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/
 */
@Component
@ConditionalOnProperty(name = "mosip.certify.data-provider-plugin.issuer.vc-sign-algo", havingValue = SignatureAlg.ED25519_SIGNATURE_SUITE_2020)
public class Ed25519Signature2020ProofGenerator implements ProofGenerator {

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
    public LdProof generateProof(LdProof vcLdProof, String vcEncodedHash, Map<String, String> keyID) {
        SignRequestDtoV2 srd = new SignRequestDtoV2();
        srd.setApplicationId(keyID.get(Constants.APPLICATION_ID));
        srd.setReferenceId(keyID.get(Constants.REFERENCE_ID));
        srd.setDataToSign(vcEncodedHash);
        srd.setResponseEncodingFormat("base58btc");
        srd.setSignAlgorithm(JWSAlgorithm.EdDSA);
        SignResponseDto s = signatureService.signv2(srd);
        return LdProof.builder().base(vcLdProof).defaultContexts(false)
                .proofValue(s.getSignature()).build();
    }
}
