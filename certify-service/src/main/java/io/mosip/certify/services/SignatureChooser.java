package io.mosip.certify.services;

import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;

import java.util.Map;

/**
 * SignatureChooser is a helper class for {@link KeymanagerLibSigner}
 *  to better deal with multiple signature algorithms.
 */
public interface SignatureChooser {
    String getName();
    Canonicalizer getCanonicalizer();
    Map<String, String> getProperties();

    LdProof getProof(LdProof vcLdProof, String sign);
}
