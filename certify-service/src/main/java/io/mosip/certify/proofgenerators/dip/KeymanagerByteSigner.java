package io.mosip.certify.proofgenerators.dip;

import com.danubetech.keyformats.crypto.ByteSigner;
import io.mosip.kernel.signature.service.SignatureServicev2;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.GeneralSecurityException;

public class KeymanagerByteSigner extends ByteSigner {

    private String appId;
    private String refId;
    private SignatureServicev2 signatureService;

    protected KeymanagerByteSigner(String algorithm, String appId, String refId,
                                   @Autowired SignatureServicev2 signatureService) {
        super(algorithm);
    }

    @Override
    protected byte[] sign(byte[] bytes) throws GeneralSecurityException {
        // business logic to call keymanager correctly based on appId, referenceId,
        //  algo, format and spit out the signature
        return null;
    }
}
