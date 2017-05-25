package org.cloudfoundry.identity.uaa.impl.config;

import brave.Tracing;
import brave.context.log4j12.MDCCurrentTraceContext;
import brave.http.HttpTracing;
import brave.servlet.TracingFilter;
import brave.spring.web.TracingClientHttpRequestInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;
import zipkin.Span;
import zipkin.reporter.AsyncReporter;
import zipkin.reporter.Reporter;
import zipkin.reporter.Sender;
import zipkin.reporter.okhttp3.OkHttpSender;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

@Configuration
public class ZipkinBraveConfig {


    @Value("${zipkin.reporting.url:http://127.0.0.1:9411/api/v1/spans}")
    private String zipkinReportingEndpoint;

    @Value("${name:predix-uaa}")
    private String serviceNameForTracing;

    /** Configuration for how to send spans to Zipkin */
    Sender sender() {
        return OkHttpSender.create(zipkinReportingEndpoint);
    }

    /** Configuration for how to buffer spans into messages for Zipkin */
    Reporter<Span> reporter() {
        return AsyncReporter.builder(sender()).build();
    }

    /** Controls aspects of tracing such as the name that shows up in the UI */
    Tracing tracing() {
        return Tracing.newBuilder()
                .localServiceName(serviceNameForTracing)
                .currentTraceContext(MDCCurrentTraceContext.create()) // puts trace IDs into logs
                .reporter(reporter()).build();
    }

    // decides how to name and tag spans. By default they are named the same as the http method.

    HttpTracing httpTracing() {
        return HttpTracing.create(tracing());
    }

    @Bean(name="tracingRestTemplate")
    public RestTemplate tracingRestTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        List<ClientHttpRequestInterceptor> interceptors =
                new ArrayList<>(restTemplate.getInterceptors());
        interceptors.add(TracingClientHttpRequestInterceptor.create(httpTracing()));
        restTemplate.setInterceptors(interceptors);
        return restTemplate;
    }

    @Bean
    public Filter tracingFilter() {
        return TracingFilter.create(httpTracing());
    }
}