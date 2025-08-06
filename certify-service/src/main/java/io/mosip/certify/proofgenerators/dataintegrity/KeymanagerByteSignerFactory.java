package io.mosip.certify.proofgenerators.dataintegrity;

import io.mosip.kernel.signature.service.SignatureServicev2;

import java.util.concurrent.ConcurrentHashMap;

public class KeymanagerByteSignerFactory {
    private static final ConcurrentHashMap<String, KeymanagerByteSigner> cache = new ConcurrentHashMap<>();

    public static KeymanagerByteSigner getInstance(String appID, String refID, SignatureServicev2 signatureService, String signAlgorithm) {
        String key = appID + ":" + refID + ":" + signAlgorithm;
        return cache.computeIfAbsent(key, k -> new KeymanagerByteSigner(appID, refID, signatureService, signAlgorithm));
    }
}