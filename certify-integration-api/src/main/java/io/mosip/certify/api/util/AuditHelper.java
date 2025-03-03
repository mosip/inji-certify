/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.api.util;

import io.mosip.certify.api.dto.AuditDTOV2;

public class AuditHelper {

    public static AuditDTOV2 buildAuditDto(String clientId) {
        AuditDTOV2 auditDTO = new AuditDTOV2();
        auditDTO.setClientId(clientId);
        auditDTO.setTransactionId(clientId);
        auditDTO.setIdType("ClientId");
        return auditDTO;
    }

    public static AuditDTOV2 buildAuditDto(String transactionId, String idType) {
        AuditDTOV2 auditDTO = new AuditDTOV2();
        auditDTO.setTransactionId(transactionId);
        auditDTO.setIdType(idType);
        return auditDTO;
    }
}
