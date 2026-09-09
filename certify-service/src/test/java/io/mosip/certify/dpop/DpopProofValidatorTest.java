package io.mosip.certify.dpop;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.util.CommonUtil;

import static org.junit.jupiter.api.Assertions.*;

class DpopProofValidatorTest {

    private static final String DOMAIN_URL = "https://certify.example.com";
    private static final String REQUEST_URI = "/v1/certify/issuance/credential";
    private static final String ACCESS_TOKEN = "an.access.token";

    private DpopProofValidator validator;
    private MockHttpServletRequest request;
    private ECKey walletKey;
    private String walletJkt;

    @BeforeEach
    void setUp() throws Exception {
        validator = new DpopProofValidator();
        ReflectionTestUtils.setField(validator, "domainUrl", DOMAIN_URL);
        ReflectionTestUtils.setField(validator, "allowedAlgorithms", Arrays.asList("ES256", "RS256", "PS256", "EdDSA"));
        ReflectionTestUtils.setField(validator, "proofMaxAgeSeconds", 60L);
        ReflectionTestUtils.setField(validator, "maxClockSkewSeconds", 10L);
        ReflectionTestUtils.setField(validator, "cacheManager",
                new ConcurrentMapCacheManager(DpopProofValidator.DPOP_JTI_CACHE));
        ReflectionTestUtils.setField(validator, "cacheType", "simple");

        request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI(REQUEST_URI);

        walletKey = new ECKeyGenerator(Curve.P_256).keyID("wallet").generate();
        walletJkt = walletKey.toPublicJWK().computeThumbprint().toString();
    }

    // ---------- happy path ----------

    @Test
    void should_accept_when_proofIsValid() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        // Returning normally is the whole assertion: the binding is checked against
        // walletJkt inside, so completing proves the thumbprint was computed and matched.
        assertDoesNotThrow(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request));
    }

    @Test
    void should_acceptHtu_when_itCarriesQueryAndFragment() throws Exception {
        // RFC 9449 §4.3: htu is compared ignoring query and fragment.
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", DOMAIN_URL + REQUEST_URI + "?x=1#frag").build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertDoesNotThrow(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request));
    }

    @Test
    void should_normalizeAwayPort_when_itIsTheSchemeDefault() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", "https://certify.example.com:443" + REQUEST_URI).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertDoesNotThrow(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request));
    }

    @Test
    void should_reject_when_htuAddsATrailingSlashToTheRequestPath() throws Exception {
        // RFC 9449 §4.3 permits dropping query and fragment and the normalizations of
        // RFC 3986 §6.2.2-6.2.3. Trailing-slash removal is in neither, and /credential
        // and /credential/ name distinct resources, so a proof bound to one must not
        // satisfy a request for the other.
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", DOMAIN_URL + REQUEST_URI + "/").build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request),
                "htu does not match");
    }

    @Test
    void should_reject_when_requestPathAddsATrailingSlashToTheHtu() throws Exception {
        // The same mismatch from the other side: the proof names the bare path and the
        // request carries the slash.
        request.setRequestURI(REQUEST_URI + "/");
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", DOMAIN_URL + REQUEST_URI).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request),
                "htu does not match");
    }

    // ---------- structure ----------

    @Test
    void should_reject_when_dpopHeaderIsMissing() {
        assertInvalid(() -> validator.validate(null, ACCESS_TOKEN, boundClaims(walletJkt), request), "missing");
    }

    @Test
    void should_reject_when_headerCarriesMultipleProofs() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof + "," + proof, ACCESS_TOKEN, boundClaims(walletJkt), request),
                "Exactly one");
    }

    @Test
    void should_reject_when_proofIsNotAJws() {
        assertInvalid(() -> validator.validate("not-a-jwt", ACCESS_TOKEN, boundClaims(walletJkt), request),
                "well-formed");
    }

    @Test
    void should_reject_when_typHeaderIsWrong() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "JWT", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "typ");
    }

    @Test
    void should_reject_when_algorithmIsNotAllowed() throws Exception {
        ReflectionTestUtils.setField(validator, "allowedAlgorithms", Arrays.asList("RS256"));
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "algorithm");
    }

    @Test
    void should_reject_when_headerHasNoJwk() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), null, "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "jwk");
    }

    @Test
    void should_reject_when_jwkCarriesPrivateMaterial() throws Exception {
        // A proof must only ever embed the public half. Nimbus refuses to *build* such a
        // header (JWSHeader.Builder.jwk() rejects a private JWK), so the header is crafted
        // by hand here - which is what a hostile client would have to do anyway.
        String validProof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(),
                "dpop+jwt", JWSAlgorithm.ES256);
        String[] parts = validProof.split("\\.");
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":" + walletKey.toJSONString() + "}";
        String crafted = com.nimbusds.jose.util.Base64URL.encode(headerJson) + "." + parts[1] + "." + parts[2];

        CertifyException e = assertThrows(CertifyException.class,
                () -> validator.validate(crafted, ACCESS_TOKEN, boundClaims(walletJkt), request));
        assertEquals(ErrorConstants.INVALID_DPOP_PROOF, e.getErrorCode());
    }

    @Test
    void should_reject_when_signatureIsFromAnotherKey() throws Exception {
        ECKey attackerKey = new ECKeyGenerator(Curve.P_256).keyID("attacker").generate();
        // Signed by the attacker, but advertising the wallet's public key.
        String proof = signProof(attackerKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "signature");
    }

    // ---------- request binding ----------

    @Test
    void should_reject_when_htmDoesNotMatchTheMethod() throws Exception {
        JWTClaimsSet claims = defaultClaims().claim("htm", "GET").build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "htm");
    }

    @Test
    void should_reject_when_htuDoesNotMatchTheUri() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", "https://evil.example.com" + REQUEST_URI).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "htu");
    }

    @Test
    void should_reject_when_proofTargetsAnotherEndpoint() throws Exception {
        // A proof minted for eSignet's /token must not be replayable at Certify.
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", "https://esignet.example.com/v1/esignet/oauth/v2/token").build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "htu");
    }

    @Test
    void should_rejectTheProof_whenHtuIsNotAbsolute() throws Exception {
        JWTClaimsSet claims = defaultClaims().claim("htu", REQUEST_URI).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "absolute");
    }

    @Test
    void should_rejectTheProof_whenHtuDoesNotParse() throws Exception {
        JWTClaimsSet claims = defaultClaims().claim("htu", "https://certify.example.com/a b").build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "not a valid URI");
    }

    @Test
    void should_blameTheServer_whenDomainUrlIsNotAbsolute() throws Exception {
        // "certify-nginx:80" parses as scheme "certify-nginx" with a null host - the exact
        // value a compose-network deployment carries. The proof below is impeccable, so
        // answering invalid_dpop_proof would send a wallet developer hunting a fault that
        // lives entirely in this deployment's configuration, and that no client can fix.
        ReflectionTestUtils.setField(validator, "domainUrl", "certify-nginx:80");
        JWTClaimsSet claims = defaultClaims().build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request));
        assertTrue(e.getMessage().contains("misconfigured"));
        assertFalse(e.getMessage().contains("certify-nginx"),
                "the offending value belongs in the log, not in a response to the caller");
    }

    @Test
    void should_blameTheServer_whenDomainUrlDoesNotParse() throws Exception {
        ReflectionTestUtils.setField(validator, "domainUrl", "https://certify.example.com/a b");
        JWTClaimsSet claims = defaultClaims().build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertThrows(IllegalStateException.class,
                () -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request));
    }

    // ---------- freshness ----------

    @Test
    void should_reject_when_proofIsOlderThanTheFreshnessWindow() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .issueTime(Date.from(Instant.now().minusSeconds(600))).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "expired");
    }

    @Test
    void should_reject_when_iatIsInTheFuture() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .issueTime(Date.from(Instant.now().plusSeconds(600))).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "future");
    }

    @Test
    void should_accept_when_iatIsWithinClockSkew() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .issueTime(Date.from(Instant.now().plusSeconds(5))).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertDoesNotThrow(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request));
    }

    @Test
    void should_reject_when_iatIsMissing() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID("jti-1")
                .claim("htm", "POST")
                .claim("htu", DOMAIN_URL + REQUEST_URI)
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, ACCESS_TOKEN))
                .build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "iat");
    }

    // ---------- token binding ----------

    @Test
    void should_reject_when_athIsForADifferentToken() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, "some.other.token")).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "ath");
    }

    @Test
    void should_reject_when_athIsTheTruncatedOidcAtHash() throws Exception {
        // Guards the CommonUtil split: at_hash keeps 128 bits, ath keeps the full digest.
        JWTClaimsSet claims = defaultClaims()
                .claim("ath", CommonUtil.generateOIDCAtHash(ACCESS_TOKEN)).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "ath");
    }

    @Test
    void should_reject_when_accessTokenIsNotDpopBound() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, Map.of("sub", "user"), request), "not DPoP-bound");
    }

    @Test
    void should_reject_when_thumbprintDoesNotMatchCnfJkt() throws Exception {
        // The wallet's own key, but a token bound to somebody else's.
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        String otherJkt = otherKey.toPublicJWK().computeThumbprint().toString();
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(otherJkt), request),
                "does not match the access token binding");
    }

    @Test
    void should_reject_when_jtiIsMissing() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issueTime(new Date())
                .claim("htm", "POST")
                .claim("htu", DOMAIN_URL + REQUEST_URI)
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, ACCESS_TOKEN))
                .build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "jti");
    }

    // ---------- replay ----------

    @Test
    void should_reject_when_proofIsReplayed() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertDoesNotThrow(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request));
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request),
                "already been used");
    }

    @Test
    void should_notBurnJti_when_proofIsRejected() throws Exception {
        // The replay check is the last thing validate() does, so a proof turned away on any
        // earlier rule must leave its jti spendable - otherwise one malformed request would
        // lock the wallet out of retrying with the same jti.
        JWTClaimsSet bad = defaultClaims().claim("htm", "GET").build();
        assertInvalid(() -> validator.validate(
                signProofUnchecked(bad), ACCESS_TOKEN, boundClaims(walletJkt), request), "htm");

        String good = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertDoesNotThrow(() -> validator.validate(good, ACCESS_TOKEN, boundClaims(walletJkt), request));
    }

    @Test
    void should_reject_when_htuIsMissing() {
        // getRequiredClaim guards this path; without a case here a regression would let a
        // proof through request binding with no htu at all.
        JWTClaimsSet noHtu = new JWTClaimsSet.Builder()
                .jwtID("jti-1")
                .issueTime(new Date())
                .claim("htm", "POST")
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, ACCESS_TOKEN))
                .build();
        assertInvalid(() -> validator.validate(
                signProofUnchecked(noHtu), ACCESS_TOKEN, boundClaims(walletJkt), request), "htu");
    }

    @Test
    void should_acceptAll_when_jtisAreDistinct() {
        for (int i = 0; i < 25; i++) {
            assertFalse(validator.checkAndMarkJti(walletJkt, "jti-" + i));
        }
    }

    @Test
    void should_acceptSameJti_when_senderKeyDiffers() {
        // RFC 9449 only requires jti to be unique per client. Keying the replay cache on
        // jti alone would let one wallet burn a value another wallet may legitimately
        // use, rejecting a valid proof as a replay.
        assertFalse(validator.checkAndMarkJti("thumbprint-a", "shared-jti"));
        assertFalse(validator.checkAndMarkJti("thumbprint-b", "shared-jti"),
                "a different sender key must have its own jti namespace");
        assertTrue(validator.checkAndMarkJti("thumbprint-a", "shared-jti"),
                "the same key replaying the same jti is still a replay");
    }

    @Test
    void should_failClosed_when_replayCacheIsMissing() {
        // A cache manager that knows nothing about dpopJti - the exact situation when the
        // cache name is left out of mosip.certify.cache.names.
        ReflectionTestUtils.setField(validator, "cacheManager",
                new ConcurrentMapCacheManager("someOtherCache"));

        CertifyException e = assertThrows(CertifyException.class,
                () -> validator.checkAndMarkJti(walletJkt, "jti-1"));
        assertEquals(ErrorConstants.INVALID_DPOP_PROOF, e.getErrorCode());
        assertTrue(e.getMessage().contains("mosip.certify.cache.names"),
                "the error should name the property that needs fixing");
    }

    @Test
    void should_admitOnlyOne_when_replaysAreConcurrent() throws Exception {
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        List<Thread> workers = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                try {
                    start.await();
                    if (!validator.checkAndMarkJti(walletJkt, "racy-jti")) {
                        accepted.incrementAndGet();
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            });
            workers.add(t);
            t.start();
        }
        start.countDown();
        for (Thread t : workers) {
            t.join();
        }

        // putIfAbsent is atomic; a get-then-put would let several threads through here.
        assertEquals(1, accepted.get(), "exactly one concurrent use of a jti may succeed");
    }

    // ---------- helpers ----------

    // ---------- reverse-proxy topology (docker-compose-injistack) ----------

    @Test
    void should_matchHtuAgainstDomainUrl_notTheUrlTheClientCalled() throws Exception {
        // docker-compose-injistack sets mosip_certify_domain_url=http://certify-nginx:80,
        // and nginx proxies to certify:8090/v1/certify/. htu is compared against that
        // configured address, never against request.getRequestURL(), which behind a proxy
        // is the container's internal view. A wallet signing the credential_endpoint it
        // read from issuer metadata therefore matches - metadata is built from the same
        // property. Note :80 is dropped as the http default before comparison.
        ReflectionTestUtils.setField(validator, "domainUrl", "http://certify-nginx:80");
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", "http://certify-nginx:80" + REQUEST_URI).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertDoesNotThrow(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request));
    }

    @Test
    void should_rejectHtuSignedOverTheHostFacingUrl_whenDomainUrlIsTheInNetworkAddress() throws Exception {
        // The same deployment seen from outside the compose network: a client reaches
        // certify on localhost:8091 and signs htu over that. It cannot match, because
        // certify only ever compares against domain.url. This is why the Postman suite,
        // which derives credentialEndpoint from certifyUrl, fails every DPoP scenario
        // against that stack until domain.url names the host-facing URL.
        ReflectionTestUtils.setField(validator, "domainUrl", "http://certify-nginx:80");
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", "http://localhost:8091" + REQUEST_URI).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request),
                "htu does not match");
    }

    // ---------- key types ----------

    @Test
    void should_accept_when_proofUsesEd25519() throws Exception {
        // RFC 9449 section 4.2 asks only for an asymmetric signature algorithm, and EdDSA
        // is one. Before OKP was handled the proof failed as "must be an asymmetric key",
        // which is the opposite of what an Ed25519 key is.
        OctetKeyPair edKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("wallet-ed").generate();
        String edJkt = edKey.toPublicJWK().computeThumbprint().toString();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("dpop+jwt")).jwk(edKey.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, defaultClaims().build());
        jwt.sign(new Ed25519Signer(edKey));

        // boundClaims(edJkt) is the assertion: an Ed25519 thumbprint computed any other
        // way would not match the binding, and validate would throw.
        assertDoesNotThrow(() -> validator.validate(jwt.serialize(), ACCESS_TOKEN, boundClaims(edJkt), request));
    }

    @Test
    void should_reject_when_okpCurveCannotSign() throws Exception {
        // X25519 is for key agreement. It is asymmetric, so the generic message would be
        // wrong; the curve is named instead.
        OctetKeyPair xKey = new OctetKeyPairGenerator(Curve.X25519).keyID("x").generate();
        OctetKeyPair edKey = new OctetKeyPairGenerator(Curve.Ed25519).generate();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("dpop+jwt")).jwk(xKey.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, defaultClaims().build());
        jwt.sign(new Ed25519Signer(edKey));

        String xJkt = xKey.toPublicJWK().computeThumbprint().toString();
        assertInvalid(() -> validator.validate(jwt.serialize(), ACCESS_TOKEN,
                boundClaims(xJkt), request), "X25519");
    }

    private JWTClaimsSet.Builder defaultClaims() {
        return new JWTClaimsSet.Builder()
                .jwtID("jti-1")
                .issueTime(new Date())
                .claim("htm", "POST")
                .claim("htu", DOMAIN_URL + REQUEST_URI)
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, ACCESS_TOKEN));
    }

    private Map<String, Object> boundClaims(String jkt) {
        return Map.of("cnf", Map.of("jkt", jkt));
    }

    private String signProof(ECKey signingKey, JWTClaimsSet claims, com.nimbusds.jose.jwk.JWK embeddedJwk,
                             String typ, JWSAlgorithm alg) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(alg).type(new JOSEObjectType(typ));
        if (embeddedJwk != null) {
            header.jwk(embeddedJwk);
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    /** signProof without the checked exception, for use inside a lambda. */
    private String signProofUnchecked(JWTClaimsSet claims) {
        try {
            return signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void assertInvalid(Runnable action, String expectedMessageFragment) {
        CertifyException e = assertThrows(CertifyException.class, action::run);
        assertEquals(ErrorConstants.INVALID_DPOP_PROOF, e.getErrorCode());
        assertTrue(e.getMessage().toLowerCase().contains(expectedMessageFragment.toLowerCase()),
                "expected message to contain '" + expectedMessageFragment + "' but was: " + e.getMessage());
    }
}
