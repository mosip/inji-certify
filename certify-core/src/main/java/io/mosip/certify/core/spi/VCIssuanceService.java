/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.spi;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;

import java.util.Map;
import java.util.List;

public interface VCIssuanceService {

    /**
     *
     * @param credentialRequest
     * @return
     */
    <T> CredentialResponse<T> getCredential(CredentialRequest credentialRequest);

    Map<String, Object> getCredentialIssuerMetadata(String version);

    Map<String, Object> getDIDDocument();

    Map<String, Object> verifyCredentialStatus(String statusListCredentialId, long statusListIndex, String statusPurpose);

    Map<String, Object> revokeCredential(String statusListId, long statusListIndex, String statusPurpose);

    List<Map<String, Object>> searchCredentials(Map<String, String> searchField);

}
