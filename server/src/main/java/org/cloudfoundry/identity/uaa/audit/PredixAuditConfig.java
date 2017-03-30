package org.cloudfoundry.identity.uaa.audit;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.ge.predix.audit.sdk.AuditCallback;
import com.ge.predix.audit.sdk.AuditClient;
import com.ge.predix.audit.sdk.FailReport;
import com.ge.predix.audit.sdk.config.AuditConfiguration;
import com.ge.predix.audit.sdk.config.vcap.VcapLoaderServiceImpl;
import com.ge.predix.audit.sdk.exception.AuditException;
import com.ge.predix.audit.sdk.exception.VcapLoadException;
import com.ge.predix.audit.sdk.message.AuditEvent;
import com.ge.predix.audit.sdk.validator.ValidatorReport;
import com.ge.predix.eventhub.EventHubClientException;

@Configuration
@Profile({ "predixaudit" })
public class PredixAuditConfig {
    private VcapLoaderServiceImpl vcapLoaderService = new VcapLoaderServiceImpl();
    private static final Logger log = LoggerFactory.getLogger(PredixAuditConfig.class);

//    @Autowired
//    private AuditClient auditClient;

    @Bean
    public AuditClient auditClient() throws AuditException, EventHubClientException {
        AuditConfiguration sdkConfig = getConfig();
        AuditCallback auditCallback = auditCallback();
        log.info("Connecting to Audit Service.");
        try {
            return new AuditClient(sdkConfig, auditCallback);
        }
        catch(AuditException | EventHubClientException e) {
            log.info("Error wiring up predixAudit Client. " + e.getMessage());
            return null;
        }
    }

    private AuditConfiguration getConfig() {
        try {
            return vcapLoaderService.getConfigFromVcap();
        } catch (VcapLoadException e) {
            log.error("Failed to load audit info from VCAP. " + e.getMessage());
        }
        return null;
    }

    public AuditCallback auditCallback() {
        return new AuditCallback() {
            @Override
            public void onValidate(AuditEvent auditEvent, List<ValidatorReport> list) {
                log.info("onValidate {}", list);
                // Check the sanitized report:
                list.forEach(validatorReport -> {
                    validatorReport.getOriginalMessage(); // Original messages
                    validatorReport.getSanitizedMessage(); // Sanitized messages
                });
            }

            @Override
            public void onFailure(AuditEvent auditEvent, FailReport failReport, String description) {
                log.info("onFailure {} \n {} \n {}", failReport, auditEvent, description);
            }

            @Override
            public void onFailure(FailReport failReport, String description) {
                log.info(String.format("onFailure %s \n %s", failReport, description));
//                if (failReport == FailReport.STREAM_IS_CLOSE){
//                    try {
//                        auditClient.reconnect();
//                    } catch (EventHubClientException e) {
//                        log.info(e.getMessage());
//                    }
//                }
            }

            @Override
            public void onSuccees(AuditEvent auditEvent) {
                log.info("onSuccess {}", auditEvent);
            }

        };
    }
}
