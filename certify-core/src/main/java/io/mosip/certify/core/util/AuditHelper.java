/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.util;

import io.mosip.certify.api.dto.AuditDTO;

public class AuditHelper {

    public static AuditDTO buildAuditDto(String transactionId, String idType) {
        AuditDTO auditDTO = new AuditDTO();
        auditDTO.setTransactionId(transactionId);
        auditDTO.setIdType(idType);
        return auditDTO;
    }
}
