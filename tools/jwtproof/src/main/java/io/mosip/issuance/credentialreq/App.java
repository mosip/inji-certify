package io.mosip.issuance.credentialreq;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.time.Duration;
import java.util.Date;


@SpringBootApplication
public class App implements CommandLineRunner {
    @Value("${nonce:}")
    private String nonce;
    @Value("${exp:}")
    private String exp;
    @Value("${aud:https://esignet-mock.collab.mosip.net}")
    private String aud;
    @Value("${iss:wallet-demo}")
    private String iss;
    private Logger LOG = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        System.out.println("Generating a proofjwt with below params:");
        System.out.println("Nonce: " + nonce);
        System.out.println("Expiry: " + exp);
        System.out.println("audience: " + aud);
        System.out.println("issuer/client-id: " + iss);
        jwtSign();
        System.exit(0);
    }
    public void jwtSign() throws JOSEException {
        OctetKeyPair edJWK = new OctetKeyPairGenerator(Curve.Ed25519)
                .generate();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.Ed25519).
                type(new JOSEObjectType("openid4vci-proof+jwt")).
                jwk(edJWK.toPublicJWK()).build();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        if (!aud.isEmpty()) {
            builder.audience(aud);
        }
        if (!nonce.isEmpty()) {
            builder.claim("nonce", nonce);
        }
        if (!iss.isEmpty()) {
            builder.issuer(iss);
        }
        Date iat = new Date();
        Duration ex;
        if (!exp.isEmpty()) {
            try {
                ex = Duration.parse(exp);
            } catch (Exception e) {
                ex = Duration.ofSeconds(3600);
                LOG.info("Invalid exp: " + exp + " defaulting to 3600 seconds");
            }
            Date exp = new Date(iat.toInstant().plusSeconds(ex.toSeconds()).toEpochMilli());
            builder.expirationTime(exp);
        }
        builder.issueTime(iat);
        JWTClaimsSet cs = builder.build();
        SignedJWT signedJWT = new SignedJWT(header, cs);
        try {
            JWSSigner signer = new Ed25519Signer(edJWK);
            // Convert to OctetKeyPair
            signedJWT.sign(signer);
            String jwtToken = signedJWT.serialize();
            System.out.println("Signed JWT: " + jwtToken);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
