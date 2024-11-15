package io.mosip.certify.services.ldsigner;

import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;

import java.util.Map;

/**
 *  ProofSignatureStrategy is a helper class for KeymanagerLibSigner
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
     * getProof takes canonicalized VC hash and returns proof using a competent
     * SignatureService implementation
     * @param vcEncodedHash
     * @return
     */
    String getProof(String vcEncodedHash);
    /**
     * buildProof takes a proof String and attaches it to a proof object as per algorithm
     * @param vcLdProof the proof object of the VC
     * @param sign should be a string, can be a detached JWS, another proofString based on implementors choice
     * @return
     */
    LdProof buildProof(LdProof vcLdProof, String sign);
}
