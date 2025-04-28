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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Ed25519SignatureAlgorithm2020 as per
 *  https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/
 */
@Component
@ConditionalOnProperty(name = "mosip.certify.data-provider-plugin.issuer.vc-sign-algo", havingValue = SignatureAlg.ED25519_SIGNATURE_SUITE_2020)
public class Ed25519Signature2020ProofGenerator implements ProofGenerator {

    private static final Logger logger = LoggerFactory.getLogger(Ed25519Signature2020ProofGenerator.class);

    @Autowired
    SignatureServicev2 signatureService;

    Canonicalizer canonicalizer = new URDNA2015Canonicalizer();

    @Override
    public String getName() {
        logger.debug("Getting name for the proof generator.");
        return SignatureAlg.ED25519_SIGNATURE_SUITE_2020;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        logger.debug("Returning canonicalizer: {}", canonicalizer.getClass().getName());
        return canonicalizer;
    }

    @Override
    public LdProof generateProof(LdProof vcLdProof, String vcEncodedHash, Map<String, String> keyID) {
        logger.info("Starting proof generation with keyID: {}", keyID);
        try {
            // Creating the sign request
            SignRequestDtoV2 srd = new SignRequestDtoV2();
            srd.setApplicationId(keyID.get(Constants.APPLICATION_ID));
            srd.setReferenceId(keyID.get(Constants.REFERENCE_ID));
            srd.setDataToSign(vcEncodedHash);
            srd.setResponseEncodingFormat("base58btc");
            srd.setSignAlgorithm(JWSAlgorithm.EdDSA);

            logger.info("SignRequestDtoV2 created with Application ID: {}, Reference ID: {}", srd.getApplicationId(), srd.getReferenceId());

            // Calling the signature service to sign
            logger.info("Signing data with algorithm: {}", JWSAlgorithm.EdDSA);
            SignResponseDto signatureResponse = signatureService.signv2(srd);

            // Logging the response from the signature service
            if (signatureResponse != null) {
                logger.info("Signature generated successfully. Signature length: {}", signatureResponse.getSignature().length());
            } else {
                logger.error("Signature response is null. Unable to generate proof.");
            }

            // Building the LdProof
            LdProof ldProof = LdProof.builder()
                    .base(vcLdProof)
                    .defaultContexts(false)
                    .proofValue(signatureResponse != null ? signatureResponse.getSignature() : null)
                    .build();

            logger.info("LdProof generated successfully.");
            return ldProof;

        } catch (Exception e) {
            logger.error("Error during proof generation: {}", e.getMessage(), e);
            throw new RuntimeException("Error while generating proof for Ed25519Signature2020", e);
        }
    }
}
