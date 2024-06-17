/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.inji.certify.core.util;

import io.inji.certify.api.dto.AuditDTO;

public class AuditHelper {

    public static AuditDTO buildAuditDto(String clientId) {
        AuditDTO auditDTO = new AuditDTO();
        auditDTO.setClientId(clientId);
        auditDTO.setTransactionId(clientId);
        auditDTO.setIdType("ClientId");
        return auditDTO;
    }

    public static AuditDTO buildAuditDto(String transactionId, String idType) {
        AuditDTO auditDTO = new AuditDTO();
        auditDTO.setTransactionId(transactionId);
        auditDTO.setIdType(idType);
        return auditDTO;
    }
}
