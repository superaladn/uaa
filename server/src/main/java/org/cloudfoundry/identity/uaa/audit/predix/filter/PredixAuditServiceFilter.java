package org.cloudfoundry.identity.uaa.audit.predix.filter;

import com.ge.predix.audit.common.message.AuditEnums;
import com.ge.predix.audit.common.message.AuditEvent;
import com.ge.predix.audit.common.message.AuditEventV2;
import com.ge.predix.audit.sdk.AuditCallback;
import com.ge.predix.audit.sdk.AuditClient;
import org.cloudfoundry.identity.uaa.audit.predix.config.LogEachBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class PredixAuditServiceFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(PredixAuditServiceFilter.class);

    @Autowired
    private AuditClient auditClient;


    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {

        filterChain.doFilter(request, response);

//        if ( (200 > response.getStatus()) || (400 <= response.getStatus())) {
//            return;
//        } else {

            AuditEvent eventV2 = AuditEventV2.builder()
                    .payload(request.getMethod()+":"+ request.getPathInfo()+": Status:"+ response.getStatus())
                    .classifier(AuditEnums.Classifier.SUCCESS)
                    .publisherType(AuditEnums.PublisherType.APP_SERVICE)
                    .categoryType(AuditEnums.CategoryType.API_CALLS)
                    .eventType(AuditEnums.EventType.ACTION)
                    .tenantUuid("uaa")
                    .correlationId(request.changeSessionId())
                    .build();

            LOGGER.info("<><><><><><><><><><><><><<><><><><>Audit-Event<><><><><><><><><><><><><><>" + eventV2.toString() );


            auditClient.audit(eventV2);

//        }


    }


}
