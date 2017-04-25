/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;


public class UaaSavedRequestAwareAuthenticationSuccessHandlerTests {

    MockHttpServletRequest request;
    MockAuthentication authentication;
    UaaSavedRequestAwareAuthenticationSuccessHandler handler;
    @Before
    public void setUp() throws Exception {
        request = new MockHttpServletRequest();
        authentication = new MockAuthentication();
        handler = new UaaSavedRequestAwareAuthenticationSuccessHandler();
    }

    @Test
    public void test_on_authentication_success() throws ServletException, IOException {
        SavedRequest savedRequest = Mockito.mock(DefaultSavedRequest.class);
        when(savedRequest.getRedirectUrl()).thenReturn("some.redirect");
        request.getSession().setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        handler.onAuthenticationSuccess(request, new MockHttpServletResponse(), authentication);
        assertEquals(request.getSession().getAttribute(FORM_REDIRECT_PARAMETER), "some.redirect");
    }

    @Test
    public void allow_url_override() {
        request.setAttribute(URI_OVERRIDE_ATTRIBUTE, "http://test.com");
        assertEquals("http://test.com", handler.determineTargetUrl(request, new MockHttpServletResponse()));
    }

    @Test
    public void form_parameter_works() {
        request.setParameter(FORM_REDIRECT_PARAMETER, "http://test.com");
        assertEquals("http://test.com", handler.determineTargetUrl(request, new MockHttpServletResponse()));
    }

    @Test
    public void form_parameter_is_overridden() {
        request.setParameter(FORM_REDIRECT_PARAMETER, "http://test.com");
        request.setAttribute(URI_OVERRIDE_ATTRIBUTE, "http://override.test.com");
        assertEquals("http://override.test.com", handler.determineTargetUrl(request, new MockHttpServletResponse()));
    }
}