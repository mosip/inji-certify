/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.util;

import com.nimbusds.jose.util.ByteUtils;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.validator.routines.UrlValidator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.*;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

import static org.apache.commons.validator.routines.UrlValidator.ALLOW_ALL_SCHEMES;
import static org.apache.commons.validator.routines.UrlValidator.ALLOW_LOCAL_URLS;

@Slf4j
public class IdentityProviderUtil {

    private static final Logger logger = LoggerFactory.getLogger(IdentityProviderUtil.class);
    public static final String ALGO_SHA_256 = "SHA-256";
    public static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private static Base64.Encoder urlSafeEncoder;
    private static PathMatcher pathMatcher;
    private static UrlValidator urlValidator;

    static {
        urlSafeEncoder = Base64.getUrlEncoder().withoutPadding();
        pathMatcher = new AntPathMatcher();
        urlValidator = new UrlValidator(ALLOW_ALL_SCHEMES+ALLOW_LOCAL_URLS);
    }

    /**
     * Output format : 2022-12-01T03:22:46.720Z
     * @return Formatted datetime
     */
    public static String getUTCDateTime() {
        return ZonedDateTime
                .now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
    }

    /**
     *  if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url
     *  encode them. The at_hash value is a case-sensitive string.
     * @param accessToken
     * @return
     * @throws CertifyException
     */
    public static String generateOIDCAtHash(String accessToken) throws CertifyException {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGO_SHA_256);
            byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
            //taking only 16 bytes (=128 bits)
            byte[] leftMost128Bits = ByteUtils.subArray(hash, 0, 16);
            return urlSafeEncoder.encodeToString(leftMost128Bits);
        } catch (NoSuchAlgorithmException ex) {
            log.error("Access token hashing failed with alg:{}", ALGO_SHA_256, ex);
            throw new CertifyException(ErrorConstants.INVALID_ALGORITHM);
        }
    }

    public static String generateRandomAlphaNumeric(int length) {
        StringBuilder builder = new StringBuilder();
        for(int i=0; i<length; i++) {
            int index = ThreadLocalRandom.current().nextInt(CHARACTERS.length());	//NOSONAR This random number generator is safe here.
            builder.append(CHARACTERS.charAt(index));
        }
        return builder.toString();
    }

    private static boolean matchUri(String registeredUri, String requestedUri) {
        return (urlValidator.isValid(registeredUri) && urlValidator.isValid(requestedUri))
                && pathMatcher.match(registeredUri, requestedUri);
    }
}
