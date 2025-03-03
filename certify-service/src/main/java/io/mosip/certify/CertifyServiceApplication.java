/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@EnableCaching
@SpringBootApplication(scanBasePackages = "io.mosip.certify,"+
        "io.mosip.kernel.crypto," +
        "io.mosip.kernel.keymanager.hsm," +
        "io.mosip.kernel.cryptomanager," +
        "io.mosip.kernel.keymanagerservice.validator,"+
        "io.mosip.kernel.keymanager,"+
        "io.mosip.kernel.cryptomanager.util," +
        "io.mosip.kernel.keymanagerservice.helper," +
        "io.mosip.kernel.keymanagerservice.repository," +
        "io.mosip.kernel.keymanagerservice.service," +
        "io.mosip.kernel.keymanagerservice.util," +
        "io.mosip.kernel.keygenerator.bouncycastle," +
        "io.mosip.kernel.signature.service," +
        "io.mosip.kernel.pdfgenerator.itext.impl,"+
        "io.mosip.kernel.partnercertservice.service," +
        "io.mosip.kernel.keymanagerservice.repository,"+
        "io.mosip.kernel.keymanagerservice.entity,"+
        "io.mosip.kernel.partnercertservice.helper," +
        "${mosip.certify.integration.scan-base-package}")
public class CertifyServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(CertifyServiceApplication.class, args);
    }
}