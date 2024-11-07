package io.mosip.certify.services.ldsigner;

import com.nimbusds.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.services.KeyManagerConstants;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;

/**
 * Ed25519SignatureAlgorithm2020 as per
 *  https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/
 * NOTE: DO-NOT-USE-NOW. This does not work correctly as per the spec and using this
 *  will result in improperly signed VCs until Keymanager supports the 2020 signature.
 */
@Component
@ConditionalOnProperty(name = "mosip.certify.issuer.vc-sign-algo", havingValue = SignatureAlg.ED25519_SIGNATURE_SUITE_2020)
public class Ed25519ProofSignature2020 implements ProofSignatureStrategy {

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
    public Map<String, String> getProperties() {
        return Map.of(KeyManagerConstants.KEY_APP_ID, KeyManagerConstants.CERTIFY_MOCK_ED25519,
                KeyManagerConstants.KEY_REF_ID, KeyManagerConstants.ED25519_REF_ID,
                KeyManagerConstants.VC_SIGN_ALGO, SignatureAlg.ED25519_SIGNATURE_SUITE_2020,
                KeyManagerConstants.KEYMGR_SIGN_ALGO, JWSAlgorithm.EdDSA.getName()
        );
    }

    @Override
    public LdProof getProof(LdProof vcLdProof, String sign) {
        // remove the jws header
        sign = sign.split("\\.\\.")[1];
        byte[] s = Base64.getUrlDecoder().decode(sign);
        return LdProof.builder().base(vcLdProof).defaultContexts(false)
                .proofValue(Multibase.encode(Multibase.Base.Base58BTC, s)).build();
    }
}
