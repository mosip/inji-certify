/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import io.mosip.certify.core.constants.Constants;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyGenerateRequestDto;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.springframework.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableJpaRepositories(basePackages = {"io.mosip.kernel.keymanagerservice.repository", "io.mosip.certify.repository"})
@EntityScan(basePackages = {"io.mosip.kernel.keymanagerservice.entity, io.mosip.certify.entity"})
@Slf4j
public class AppConfig implements ApplicationRunner {

    @Value("${mosip.certify.default.httpclient.connections.max.per.host:20}")
    private int defaultMaxConnectionPerRoute;

    @Value("${mosip.certify.default.httpclient.connections.max:100}")
    private int defaultTotalMaxConnection;

    @Autowired
    private KeymanagerService keymanagerService;

    @Value("${mosip.certify.cache.security.secretkey.reference-id}")
    private String cacheSecretKeyRefId;


    @Bean
    public ObjectMapper objectMapper() {
        return JsonMapper.builder()
                .addModule(new AfterburnerModule())
                .addModule(new JavaTimeModule())
                .build();
    }

    @Bean
    public RestTemplate restTemplate() {
        HttpClientBuilder httpClientBuilder = HttpClients.custom()
                .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                        .setMaxConnPerRoute(defaultMaxConnectionPerRoute)
                        .setMaxConnTotal(defaultTotalMaxConnection)
                        .build())
                .disableCookieManagement();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClientBuilder.build());
        return new RestTemplate(requestFactory);
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("===================== CERTIFY_SERVICE ROOT KEY CHECK ========================");
        String objectType = "CSR";
        KeyPairGenerateRequestDto rootKeyRequest = new KeyPairGenerateRequestDto();
        rootKeyRequest.setApplicationId(Constants.ROOT_KEY);
        // Set the reference id to empty string, as keymanager is expecting the same for initialization
        rootKeyRequest.setReferenceId(org.apache.commons.lang3.StringUtils.EMPTY);
        keymanagerService.generateMasterKey(objectType, rootKeyRequest);
        log.info("===================== CERTIFY_SERVICE MASTER KEY CHECK ========================");
        KeyPairGenerateRequestDto masterKeyRequest = new KeyPairGenerateRequestDto();
        masterKeyRequest.setApplicationId(Constants.CERTIFY_SERVICE_APP_ID);
        // Set the reference id to empty string, as keymanager is expecting the same for initialization
        masterKeyRequest.setReferenceId(org.apache.commons.lang3.StringUtils.EMPTY);
        keymanagerService.generateMasterKey(objectType, masterKeyRequest);
        // TODO: Generate an EC & ED key via K8s Job(INJICERT-469)
        KeyPairGenerateRequestDto rsaKeyRequest = new KeyPairGenerateRequestDto();
        rsaKeyRequest.setApplicationId(Constants.CERTIFY_VC_SIGN_RSA);
        rsaKeyRequest.setReferenceId(Constants.EMPTY_REF_ID);
        rsaKeyRequest.setForce(false);
        keymanagerService.generateMasterKey("certificate", rsaKeyRequest);
        if(!StringUtils.isEmpty(cacheSecretKeyRefId)) {
            SymmetricKeyGenerateRequestDto symmetricKeyGenerateRequestDto = new SymmetricKeyGenerateRequestDto();
            symmetricKeyGenerateRequestDto.setApplicationId(Constants.CERTIFY_SERVICE_APP_ID);
            symmetricKeyGenerateRequestDto.setReferenceId(cacheSecretKeyRefId);
            symmetricKeyGenerateRequestDto.setForce(false);
            keymanagerService.generateSymmetricKey(symmetricKeyGenerateRequestDto);
            log.info("============= CERTIFY_SERVICE CACHE SYMMETRIC KEY CHECK COMPLETED =============");
        }

        log.info("===================== CERTIFY_PARTNER MASTER KEY CHECK ========================");
        KeyPairGenerateRequestDto partnerMasterKeyRequest = new KeyPairGenerateRequestDto();
        partnerMasterKeyRequest.setApplicationId(Constants.CERTIFY_PARTNER_APP_ID);
        // Set the reference id to empty string, as keymanager is expecting the same for initialization
        partnerMasterKeyRequest.setReferenceId(org.apache.commons.lang3.StringUtils.EMPTY);
        keymanagerService.generateMasterKey(objectType, partnerMasterKeyRequest);
        // Generate an Ed25519Key:
        // 1. Generate a master key first to enable Keymanager to store the key.
        KeyPairGenerateRequestDto storeKey = new KeyPairGenerateRequestDto();
        storeKey.setApplicationId(Constants.CERTIFY_VC_SIGN_ED25519);
        storeKey.setReferenceId(Constants.EMPTY_REF_ID);
        keymanagerService.generateMasterKey("certificate", storeKey);
        // 2. Generate an Ed25519 key later
        KeyPairGenerateRequestDto ed25519Req = new KeyPairGenerateRequestDto();
        ed25519Req.setApplicationId(Constants.CERTIFY_VC_SIGN_ED25519);
        ed25519Req.setReferenceId(Constants.ED25519_REF_ID);
        keymanagerService.generateECSignKey("certificate", ed25519Req);
        log.info("===================== CERTIFY KEY SETUP COMPLETED ========================");
    }
}
