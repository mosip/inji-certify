/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;


@ConditionalOnProperty(value = "spring.cache.type", havingValue = "redis")
@Configuration
@Slf4j
public class RedisCacheConfig {

    @Value("#{${mosip.certify.cache.expire-in-seconds}}")
    private Map<String, Integer> cacheNamesWithTTLMap;

    @Value("${mosip.certify.cache.redis.key-prefix:}")
    private String cachePrefix;

    @Bean
    public RedisCacheManagerBuilderCustomizer redisCacheManagerBuilderCustomizer() {
        return (builder) -> {
            Map<String, RedisCacheConfiguration> configurationMap = new HashMap<>();
            cacheNamesWithTTLMap.forEach((cacheName, ttl) -> {
                RedisCacheConfiguration defaultConfiguration = RedisCacheConfiguration
                                .defaultCacheConfig()
                                .disableCachingNullValues()
                                .entryTtl(Duration.ofSeconds(ttl));
                if (cachePrefix != null && !cachePrefix.isEmpty()) {
                    log.info("Using cache prefix: {}", cachePrefix);
                    defaultConfiguration = defaultConfiguration.prefixCacheNameWith(cachePrefix);
                }
                configurationMap.put(cacheName, defaultConfiguration);
            });
            builder.withInitialCacheConfigurations(configurationMap);
        };
    }
}
