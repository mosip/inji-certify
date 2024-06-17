package io.inji.certify;


import io.inji.certify.api.dto.AuditDTO;
import io.inji.certify.api.spi.AuditPlugin;
import io.inji.certify.api.util.Action;
import io.inji.certify.api.util.ActionStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;


@ConditionalOnProperty(value = "mosip.certify.integration.audit-plugin", havingValue = "TestAuditPlugin")
@Component
@Slf4j
public class TestAuditPluginImpl implements AuditPlugin {

    @Override
    public void logAudit(Action action, ActionStatus status, AuditDTO audit, Throwable t) {
        //do nothing
    }

    @Override
    public void logAudit(String username, Action action, ActionStatus status, AuditDTO audit, Throwable t) {
        //do nothing
    }
}