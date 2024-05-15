package io.mosip.certify.api.util;

public enum Action {
    VC_ISSUANCE("vci-service");

    String module;

    Action(String module) {
        this.module = module;
    }

    public String getModule() {
        return this.module;
    }
}
