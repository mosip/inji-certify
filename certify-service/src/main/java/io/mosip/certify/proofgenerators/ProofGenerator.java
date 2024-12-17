package io.mosip.certify.proofgenerators;

import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;

import java.util.Map;

/**
 *  ProofGenerator is a helper class for KeymanagerLibSigner
 *  to better deal with multiple signature algorithms for JSON-LD VCs.
 */
public interface ProofGenerator {
    /**
     * @return returns the name of the Algorithm
     */
    String getName();

    /**
     * @return the Canonicalizer which will be used to Canonicalize the templated VC
     */
    Canonicalizer getCanonicalizer();

    /**
     * generateProof takes a canonicalized VC hash generates a proof and
     *  returns an LdProof object.
     *  signature: can be a detached JWS, or another proofString based on implementors choice
     *
     * @param vcLdProof the proof object of the VC
     * @param vcHash is the output of the
     * @return
     */
    LdProof generateProof(LdProof vcLdProof, String vcHash, Map<String, String> keyID);
}
