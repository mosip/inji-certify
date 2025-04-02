/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.plugin.impl;

import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import io.mosip.certify.api.dto.AuditDTOV2;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@ConditionalOnProperty(value = "mosip.certify.integration.audit-plugin", havingValue = "LoggerAuditService")
@Component
@Slf4j
public class LoggerAuditService implements AuditPlugin {

	@Async
    @Override
    public void logAudit(@NotNull Action action, @NotNull ActionStatus status, @NotNull AuditDTOV2 auditDTO, Throwable t) {
        audit(null, action, status, auditDTO, t);
    }
    
    @Async
    @Override
	public void logAudit(String username, Action action, ActionStatus status, AuditDTOV2 auditDTO, Throwable t) {
    	audit(username, action, status, auditDTO, t);
	}

    private void addAuditDetailsToMDC(AuditDTOV2 auditDTO) {
        if(auditDTO != null) {
            MDC.put("transactionId", auditDTO.getTransactionId());
        }
    }
    
    public void audit(String username, Action action, ActionStatus status, AuditDTOV2 auditDTO, Throwable t) {
    	addAuditDetailsToMDC(auditDTO);
        try {
            if(t != null) {
                log.error(action.name(), t);
                return;
            }

            switch (status) {
                case ERROR:
                    log.error(action.name());
                    break;
                default:
                    log.info(username != null ? "Sessionuser: " +username+ "with action: " +action.name() : action.name());
            }
        } finally {
            MDC.clear();
        }
    }
}
