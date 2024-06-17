/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.inji.certify.core.config;

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
public class RedisCacheConfig {

    @Value("#{${mosip.certify.cache.expire-in-seconds}}")
    private Map<String, Integer> cacheNamesWithTTLMap;

    @Bean
    public RedisCacheManagerBuilderCustomizer redisCacheManagerBuilderCustomizer() {
        return (builder) -> {
            Map<String, RedisCacheConfiguration> configurationMap = new HashMap<>();
            cacheNamesWithTTLMap.forEach((cacheName, ttl) -> {
                configurationMap.put(cacheName, RedisCacheConfiguration
                                .defaultCacheConfig()
                                    .disableCachingNullValues()
                                    .entryTtl(Duration.ofSeconds(ttl)));
            });
            builder.withInitialCacheConfigurations(configurationMap);
        };
    }
}
