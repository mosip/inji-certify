package io.mosip.certify.services.ldsigner;

import com.nimbusds.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.services.KeyManagerConstants;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@ConditionalOnProperty(name = "mosip.certify.issuer.vc-sign-algo", havingValue = SignatureAlg.RSA_SIGNATURE_SUITE)
public class RsaProofSignature2018 implements ProofSignatureStrategy {

    Canonicalizer canonicalizer = new URDNA2015Canonicalizer();

    @Override
    public String getName() {
        return SignatureAlg.RSA_SIGNATURE_SUITE;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    @Override
    public Map<String, String> getProperties() {
        return Map.of(KeyManagerConstants.KEY_APP_ID, KeyManagerConstants.CERTIFY_MOCK_RSA,
                KeyManagerConstants.KEY_REF_ID, KeyManagerConstants.EMPTY_REF_ID,
                KeyManagerConstants.VC_SIGN_ALGO, SignatureAlg.RSA_SIGNATURE_SUITE,
                KeyManagerConstants.KEYMGR_SIGN_ALGO, JWSAlgorithm.RS256.getName()
                );
    }

    @Override
    public LdProof getProof(LdProof vcLdProof, String sign) {
        return LdProof.builder().base(vcLdProof).defaultContexts(false)
                .jws(sign).build();
    }
}
