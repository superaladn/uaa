package org.cloudfoundry.identity.uaa.audit.predix.config;

import com.ge.predix.audit.common.message.AuditEvent;
import com.ge.predix.audit.common.validator.ValidatorReport;
import com.ge.predix.audit.sdk.AuditCallback;
import com.ge.predix.audit.sdk.FailReport;
import com.ge.predix.audit.sdk.config.AuditConfiguration;
import com.ge.predix.audit.sdk.config.vcap.VcapLoaderService;
import com.ge.predix.audit.sdk.exception.VcapLoadException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.Arrays;
import java.util.List;

@Configuration
//@Profile({ "cloud" })
@ComponentScan("com.ge.predix.audit.sdk")
public class AuditServiceConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuditServiceConfig.class);

    @Autowired
    private VcapLoaderService vcapLoaderService;


    @Bean
    public AuditConfiguration auditConfiguration() throws VcapLoadException {
        AuditConfiguration config = vcapLoaderService.getConfigFromVcap();
        return config;
    }

    @Bean
    public AuditCallback auditCallback(){
        return new AuditCallback() {
            @Override
            public void onValidate(AuditEvent auditEvent, List<ValidatorReport> list) {
                LOGGER.info("onValidate {}", list);
                //Check the sanitized report:
                list.forEach( validatorReport -> {
                    validatorReport.isValid(); //Result
                    validatorReport.getOriginalMessage(); //Original messages
                    validatorReport.getSanitizedMessage(); //Sanitized messages
                });

            }

            @Override
            public void onFailure(AuditEvent auditEvent, FailReport failReport, String description) {
                LOGGER.info("onFailure {} \n {} \n {}", failReport, auditEvent, description);
            }

            @Override
            public void onFailure(FailReport failReport, String description) {
                LOGGER.info("onFailure {} \n {}", failReport, description);
            }

            @Override
            public void onSuccees(AuditEvent auditEvent) {
                LOGGER.info("onSuccees {}", auditEvent);
            }
        };
    }





}
