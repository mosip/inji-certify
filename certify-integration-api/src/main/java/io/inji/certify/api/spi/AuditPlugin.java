/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.inji.certify.api.spi;

import io.inji.certify.api.dto.AuditDTO;
import io.inji.certify.api.util.Action;
import io.inji.certify.api.util.ActionStatus;

public interface AuditPlugin {

    /**
     + Plugin method to audit all the actions in certify service.
     +
     +  @param action Action to audit @{@link Action}
     +  @param actionStatus Action status to audit @{@link ActionStatus}
     +  @param audit @{@link AuditDTO} during this action
     +  @param t Any error / exception occurred during this action, null if no errors / exception found.
     */
    void logAudit(Action action, ActionStatus status, AuditDTO audit, Throwable t);

    /**
    + Plugin method to audit all the actions in certify service.
    +
    +  @param username Session username for audit
    +  @param action Action to audit @{@link Action}
    +  @param actionStatus Action status to audit @{@link ActionStatus}
    +  @param audit @{@link AuditDTO} during this action
    +  @param t Any error / exception occurred during this action, null if no errors / exception found.
    */
	void logAudit(String username, Action action, ActionStatus status, AuditDTO audit, Throwable t);
}
