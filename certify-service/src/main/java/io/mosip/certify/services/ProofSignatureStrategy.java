package io.mosip.certify.services;

import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;

import java.util.Map;

/**
 *  ProofSignatureStrategy is a helper class for {@link KeymanagerLibSigner}
 *  to better deal with multiple signature algorithms for JSON-LD VCs.
 */
public interface ProofSignatureStrategy {
    /**
     * @return returns the name of the Algorithm
     */
    String getName();

    /**
     * @return the Canonicalizer which will be used to Canonicalize the templated VC
     */
    Canonicalizer getCanonicalizer();

    /**
     * @return the KeyManager properties for VC Signing
     */
    Map<String, String> getProperties();

    /**
     * @param vcLdProof the proof object of the VC
     * @param sign should be a string, can be a detached JWS, another proofString based on implementors choice
     * @return
     */
    LdProof getProof(LdProof vcLdProof, String sign);
}
