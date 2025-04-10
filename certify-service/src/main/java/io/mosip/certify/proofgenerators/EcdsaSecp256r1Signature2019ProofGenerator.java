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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * EcdsaSecp256r1Signature2019 as per https://w3c.github.io/cg-reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/
 * secp256r1/P-256
 */
@Component
@ConditionalOnProperty(name = "mosip.certify.data-provider-plugin.issuer.vc-sign-algo", havingValue = SignatureAlg.EC_SECP256R1_2019)
public class EcdsaSecp256r1Signature2019ProofGenerator implements ProofGenerator {

    @Autowired
    SignatureServicev2 signatureService;

    Canonicalizer canonicalizer = new URDNA2015Canonicalizer();

    @Override
    public String getName() {
        return SignatureAlg.EC_SECP256R1_2019;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    @Override
    public LdProof generateProof(LdProof vcLdProof, String vcEncodedHash, Map<String, String> keyID) {
        SignRequestDtoV2 srd = new SignRequestDtoV2();
        srd.setDataToSign(vcEncodedHash);
        srd.setApplicationId(keyID.get(Constants.APPLICATION_ID));
        srd.setResponseEncodingFormat("base58btc");
        srd.setReferenceId(keyID.get(Constants.REFERENCE_ID));
        srd.setSignAlgorithm(JWSAlgorithm.ES256);
        SignResponseDto jwsSignedData = signatureService.signv2(srd);
        return LdProof.builder().base(vcLdProof).defaultContexts(false)
                .proofValue(jwsSignedData.getSignature()).build();
    }
}
