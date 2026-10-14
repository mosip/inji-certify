package io.mosip.certify.api.util;

public enum Action {
    VC_ISSUANCE("vci-service"),

    PROOF_VALIDATION("proof-validation"),

    PROOF_VALIDATION_SKIPPED("proof-validation"),

    NONCE_VALIDATION("nonce-validation");

    String module;

    Action(String module) {
        this.module = module;
    }

    public String getModule() {
        return this.module;
    }
}
