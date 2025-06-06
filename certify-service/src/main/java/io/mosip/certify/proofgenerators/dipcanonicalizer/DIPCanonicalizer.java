package io.mosip.certify.proofgenerators.dipcanonicalizer;

import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizers;
import foundation.identity.jsonld.JsonLDObject;

/**
 * Canonicalizer is a class that provides a method to canonicalize JSON-LD objects
 * using a specified algorithm. It is used in the context of generating data integrity
 * proofs for verifiable credentials.
 */
// TODO: Should this be a an implementation to an interface?
public class DIPCanonicalizer {
    public String perform(String algo, JsonLDObject input) {
        // 1. Find Canonicalizer for the given algorithm
        Canonicalizer c = Canonicalizers.findDefaultCanonicalizerByAlgorithm(algo);
        // 2. Perform canonicalization using the found Canonicalizer
        return null;
    }
}
