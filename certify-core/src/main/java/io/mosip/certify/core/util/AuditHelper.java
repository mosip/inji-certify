/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.util;

import io.mosip.certify.api.dto.AuditDTO;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;

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

    public static String getClaimValue(SecurityContext context, String claimName) {
        if (context.getAuthentication() == null) {
            return null;
        }
        if (context.getAuthentication().getPrincipal() == null) {
            return null;
        }
        if (context.getAuthentication().getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) context.getAuthentication().getPrincipal();
            return jwt.getClaim(claimName);
        }
        return null;
    }
}
