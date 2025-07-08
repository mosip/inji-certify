package io.mosip.certify.proofgenerators;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public class ProofGeneratorFactory {
    @Autowired
    private List<ProofGenerator> proofGenerators;

    /**
     * Factory method to create ProofGenerator based on the given algorithm name.
     *
     * @param vcSignCryptoSuite the name of the algorithm
     * @return an instance of ProofGenerator
     */
    public Optional<ProofGenerator> getProofGenerator(String vcSignCryptoSuite) {
        if(vcSignCryptoSuite == null) {
            return null;
        }
        return proofGenerators.stream()
                .filter(proofGenerator -> proofGenerator.getName().equals(vcSignCryptoSuite))
                .findFirst();
    }
}
