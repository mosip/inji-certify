/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.api.spi;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;

import java.util.Map;
/**
 * VCIssuancePlugin is implemented by VC plugin
 *  implementors who want to make use of an existing VC Issuance Infrastructure
 *  or want to do everything by themselves to generate the VC from the plugin.
 *  VC is received by the plugin and sent to Certify and forwarded to the
 *  client applications.
 */
public interface VCIssuancePlugin {

    /**
     * Applicable for formats : ldp_vc
     * @param vcRequestDto
     * @param holderId Holders key material as either DID / KID. This should be used for cryptographic binding of the VC
     * @param identityDetails Parsed access-token or introspect endpoint response if token is opaque.
     * @return
     */
    VCResult<JsonLDObject> getVerifiableCredentialWithLinkedDataProof(VCRequestDto vcRequestDto, String holderId,
                                                                      Map<String, Object> identityDetails) throws VCIExchangeException;

    /**
     * Applicable for formats : jwt_vc_json, jwt_vc_json-ld, mso_doc
     * @param vcRequestDto
     * @param holderId
     * @param identityDetails
     * @return
     */
    VCResult<String> getVerifiableCredential(VCRequestDto vcRequestDto, String holderId,
                                                                             Map<String, Object> identityDetails) throws VCIExchangeException;
}
