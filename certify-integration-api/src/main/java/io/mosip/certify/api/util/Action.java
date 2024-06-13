/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.api.util;

public enum Action {
    VC_ISSUANCE("vci-service"),
    UPLOAD_CERTIFICATE("keymanager"),
    GET_CERTIFICATE("keymanager");

    String module;

    Action(String module) {
        this.module = module;
    }

    public String getModule() {
        return this.module;
    }
}
