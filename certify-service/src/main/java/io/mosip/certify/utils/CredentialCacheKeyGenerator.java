/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static io.mosip.certify.core.constants.Constants.DELIMITER;

@Component("credentialCacheKeyGenerator") // Bean name used in SpEL
public class CredentialCacheKeyGenerator {

    private static final Logger log = LoggerFactory.getLogger(CredentialCacheKeyGenerator.class);
    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private CacheManager cacheManager;

    public String generateKeyFromCredentialConfigKeyId(String credentialConfigKeyId) {
        if (credentialConfigKeyId == null) {
            log.warn("generateKeyFromConfigId called with null configId for cache key generation.");
            return null;
        }

        Optional<CredentialConfig> configOpt = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if (configOpt.isPresent()) {
           CredentialConfig config = configOpt.get();

           if(config.getCredentialFormat().equals(VCFormats.VC_SD_JWT)){
                return String.join(DELIMITER,
                          config.getCredentialFormat(),
                          config.getSdJwtVct());
           }

           return String.join(DELIMITER,
                       config.getCredentialType(),
                       config.getContext(),
                       config.getCredentialFormat());
        }

        return  "default-key";
    }
}