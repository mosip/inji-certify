/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public class ProofValidatorFactory {

    @Autowired
    private List<ProofValidator> proofValidators;

    public ProofValidator getProofValidator(String proofType) {
        Optional<ProofValidator> result = proofValidators.stream()
                .filter(v -> v.getProofType().equals(proofType))
                .findFirst();

        if(result.isPresent())
            return result.get();

        throw new CertifyException(ErrorConstants.UNSUPPORTED_PROOF_TYPE);
    }

}
