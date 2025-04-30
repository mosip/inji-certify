/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import io.ipfs.multibase.Multibase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;

import java.text.ParseException;
import java.util.*;

public class DIDkeysProofManager implements JwtProofKeyManager {
    public static final String DID_KEY_PREFIX = "did:key:";

    @Override
    public Optional<JWK> getKeyFromHeader(JWSHeader header) {
        if(Objects.nonNull(header.getJWK()))
            return Optional.ofNullable(header.getJWK());
        byte b[] = Multibase.decode(header.getKeyID().split("did:key:")[1]);
        // full list of keys and their multibase prefixes available here: https://github.com/multiformats/multicodec/blob/master/table.csv
        // NOTE: https://w3c-ccg.github.io/did-key-spec/#signature-method-creation-algorithm
        if ((b[0] == (byte) 0xed && b[1] == (byte) 0x01) && b.length == 34) {
            try {
                JWK edKey = JWK.parse(Map.of("kty", "OKP", "crv", "Ed25519",
                        "x", Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(b, 2, 34))));
                return Optional.of(edKey);
            } catch (ParseException e) {
                return null;
            }
        } else if (b[0] == (byte) 0xe7 && b[1] == (byte) 0x01 && b.length == 35) {
            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
            ECCurve curve = params.getCurve();
            ECPoint ecPoint = curve.decodePoint(Arrays.copyOfRange(b, 2, b.length));
            // Extract x and y coordinates
            byte[] xBytes = ecPoint.getAffineXCoord().toBigInteger().toByteArray();
            byte[] yBytes = ecPoint.getAffineYCoord().toBigInteger().toByteArray();

            // Normalize to 32-byte arrays (secp256k1 uses 256-bit coordinates)
            xBytes = Arrays.copyOfRange(xBytes, xBytes.length - 32, xBytes.length);
            yBytes = Arrays.copyOfRange(yBytes, yBytes.length - 32, yBytes.length);
            JWK j = new ECKey.Builder(Curve.SECP256K1, Base64URL.encode(xBytes), Base64URL.encode(yBytes)).build();
            return Optional.of(j);
        } else if (b[0] == (byte) 0x80 && b[1] == (byte) 0x24 && b.length == 35) {
            // TODO: should be 0x1200 instead
            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECCurve curve = params.getCurve();
            ECPoint ecPoint = curve.decodePoint(Arrays.copyOfRange(b, 2, b.length));
            byte[] xBytes = ecPoint.getAffineXCoord().toBigInteger().toByteArray();
            byte[] yBytes = ecPoint.getAffineYCoord().toBigInteger().toByteArray();

            xBytes = Arrays.copyOfRange(xBytes, xBytes.length - 32, xBytes.length);
            yBytes = Arrays.copyOfRange(yBytes, yBytes.length - 32, yBytes.length);
            JWK j = new ECKey.Builder(Curve.P_256, Base64URL.encode(xBytes), Base64URL.encode(yBytes)).build();
            return Optional.of(j);
        } else if (b[0] == (byte) 0x85 && b[1] == (byte) 0x24) {
            // RSA2048
            ASN1InputStream asn1 = new ASN1InputStream(Arrays.copyOfRange(b, 2, b.length));
            try {
                ASN1Sequence seq = (ASN1Sequence) asn1.readObject();
                if (seq.size() != 2) {
                    // missing modulus or exponent
                   return Optional.empty();
                }
                BigInteger modulus = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
                BigInteger exponent = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();

                // Construct JWK
                JWK rsaKey = new RSAKey.Builder(Base64URL.encode(modulus), Base64URL.encode(exponent))
                        .build();

                return Optional.of(rsaKey);
            } catch (IOException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<String> getDID(JWSHeader header) {
        if (header.getKeyID().startsWith(DID_KEY_PREFIX)) {
            return Optional.of(header.getKeyID());
        }
        return Optional.empty();
    }
}
