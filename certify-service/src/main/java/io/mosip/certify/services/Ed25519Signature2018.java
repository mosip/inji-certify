package io.mosip.certify.services;

import com.nimbusds.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.SignatureAlg;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Ed25519SignatureAlgorithm2018 as per https://w3c-ccg.github.io/lds-ed25519-2018/
 */
@Component
@ConditionalOnProperty(name = "mosip.certify.issuer.vc-sign-algo", havingValue = SignatureAlg.ED25519_SIGNATURE_SUITE)
public class Ed25519Signature2018 implements SignatureChooser {

    @Override
    public String getName() {
        return SignatureAlg.ED25519_SIGNATURE_SUITE;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        return new URDNA2015Canonicalizer();
    }

    @Override
    public Map<String, String> getProperties() {
        return Map.of(KeyManagerConstants.KEY_APP_ID, KeyManagerConstants.CERTIFY_MOCK_ED25519,
                KeyManagerConstants.KEY_REF_ID, KeyManagerConstants.ED25519_REF_ID,
                KeyManagerConstants.VC_SIGN_ALGO, SignatureAlg.ED25519_SIGNATURE_SUITE,
                KeyManagerConstants.KEYMGR_SIGN_ALGO, JWSAlgorithm.EdDSA.getName()
        );
    }

    @Override
    public LdProof getProof(LdProof vcLdProof, String sign) {
        return LdProof.builder().base(vcLdProof).defaultContexts(false)
                .jws(sign).build();
    }
}
