/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.inji.certify.core.spi;

import io.inji.certify.core.dto.CredentialRequest;
import io.inji.certify.core.dto.CredentialResponse;

import java.util.Map;

public interface VCIssuanceService {

    /**
     *
     * @param credentialRequest
     * @return
     */
    <T> CredentialResponse<T> getCredential(CredentialRequest credentialRequest);

    Map<String, Object> getCredentialIssuerMetadata(String version);
}
