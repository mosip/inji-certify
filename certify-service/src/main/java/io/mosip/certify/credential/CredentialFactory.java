package io.mosip.certify.credential;

import io.mosip.certify.enums.CredentialFormat;
import lombok.extern.slf4j.Slf4j;



/***
 * Credential Factory class
 **/
@Slf4j
public class CredentialFactory {

    // Factory method to create objects based on type
    public static Credential getCredential(CredentialFormat format) {
        if (format == null) {
            return null;
        }
        switch (format) {
            /*case VC_SD_JWT -> {
                yield "VC_SD_JWT processed"; // 'yield' returns value from case
            }*/
            case SD_JWT -> {
                return new SDJWT();
            }
            case VC_LDP -> {
                return new W3cJsonLd();
            }
            default -> {
               log.error("unknown credential format {}", format);
                return null;
            }
        }
    }
}