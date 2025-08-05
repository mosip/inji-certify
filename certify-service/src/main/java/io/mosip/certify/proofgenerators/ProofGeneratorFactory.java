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
     * @param signatureCryptoSuite the name of the algorithm
     * @return an instance of ProofGenerator
     */
    public Optional<ProofGenerator> getProofGenerator(String signatureCryptoSuite) {
        if(signatureCryptoSuite == null) {
            return Optional.empty();
        }
        return proofGenerators.stream()
                .filter(proofGenerator -> proofGenerator.getName().equals(signatureCryptoSuite))
                .findFirst();
    }
}
