/*
 *  Copyright (c) 2012-2015 VMware, Inc.  All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not
 *  use this file except in compliance with the License.  You may obtain a copy
 *  of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, without
 *  warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */

package com.vmware.identity.openidconnect.server;

import static com.vmware.identity.openidconnect.server.TestContext.GSS_CONTEXT_ID;
import static com.vmware.identity.openidconnect.server.TestContext.NONCE;
import static com.vmware.identity.openidconnect.server.TestContext.PASSWORD;
import static com.vmware.identity.openidconnect.server.TestContext.SESSION_COOKIE_NAME;
import static com.vmware.identity.openidconnect.server.TestContext.SESSION_ID;
import static com.vmware.identity.openidconnect.server.TestContext.STATE;
import static com.vmware.identity.openidconnect.server.TestContext.USERNAME;
import static com.vmware.identity.openidconnect.server.TestContext.authnController;
import static com.vmware.identity.openidconnect.server.TestContext.authnRequestParameters;
import static com.vmware.identity.openidconnect.server.TestContext.gssLoginString;
import static com.vmware.identity.openidconnect.server.TestContext.idmClient;
import static com.vmware.identity.openidconnect.server.TestContext.idmClientBuilder;
import static com.vmware.identity.openidconnect.server.TestContext.initialize;
import static com.vmware.identity.openidconnect.server.TestContext.passwordLoginString;
import static com.vmware.identity.openidconnect.server.TestContext.validateAuthnSuccessResponse;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.Cookie;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.servlet.ModelAndView;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.Scope;

/**
 * @author Yehia Zayour
 */
public class LoginTest {
    @BeforeClass
    public static void setup() throws Exception {
        initialize();
    }

    @Test
    public void testPasswordLogin() throws Exception {
        String loginString = passwordLoginString();
        assertSuccessResponse(loginString);
    }

    @Test
    public void testPasswordLoginIncorrectCredentials() throws Exception {
        String loginString = passwordLoginString(USERNAME + "_non_matching", PASSWORD + "_non_matching");
        assertErrorResponse(loginString, 401, "Unauthorized: Incorrect username/password", null);
    }

    @Test
    public void testPasswordLoginInvalidLoginString() throws Exception {
        String loginString = passwordLoginString() + " extra";
        assertErrorResponse(loginString, 400, "invalid_request: malformed password login string", null);
    }

    @Test
    public void testPasswordLoginInvalidUsernamePassword() throws Exception {
        String unp = "usernamepassword"; // should be username:password
        String unp64 = Base64.encode(unp).toString();
        String loginString = "Basic " + unp64;
        assertErrorResponse(loginString, 400, "invalid_request: malformed username:password in login string", null);
    }

    @Test
    public void testGssLoginOneLegged() throws Exception {
        String loginString = gssLoginString();
        assertSuccessResponse(loginString);
    }

    @Test
    public void testGssLoginTwoLegged() throws Exception {
        String contextId = GSS_CONTEXT_ID;
        String loginString = gssLoginString(contextId);
        IdmClient idmClient = idmClientBuilder().gssServerLeg(new byte[1]).build();
        assertErrorResponse(loginString, 401, "Unauthorized: continue Negotiate required", "Negotiate " + contextId, idmClient);
    }

    @Test
    public void testGssLoginInvalidTicket() throws Exception {
        String contextId = GSS_CONTEXT_ID + "non_matching";
        String loginString = gssLoginString(contextId);
        assertErrorResponse(loginString, 401, "Unauthorized: invalid gss token", null);
    }

    @Test
    public void testGssLoginInvalidLoginString() throws Exception {
        String loginString = gssLoginString() + " extra";
        assertErrorResponse(loginString, 400, "invalid_request: malformed gss login string", null);
    }

    @Test
    public void testInvalidLoginMethod() throws Exception {
        String loginString = "invalid_method";
        assertErrorResponse(loginString, 400, "invalid_request: invalid login method", null);
    }

    @Test
    public void testSessionLogin() throws Exception {
        Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, SESSION_ID);
        Pair<ModelAndView, MockHttpServletResponse> result = doRequest(null /* loginString */, sessionCookie);
        ModelAndView modelView = result.getLeft();
        MockHttpServletResponse response = result.getRight();
        Assert.assertNull("modelView", modelView);
        Assert.assertNull("sessionCookie", response.getCookie(SESSION_COOKIE_NAME));
        validateAuthnSuccessResponse(response, Flow.AUTHZ_CODE, new Scope("openid"), false, false, STATE, NONCE);
    }

    @Test
    public void testLoginStringWithSessionCookieMatching() throws Exception {
        // if request has both a loginString and session cookie, then if the session cookie matches, use it and ignore the loginString
        String loginString = passwordLoginString();
        Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, SESSION_ID);
        Pair<ModelAndView, MockHttpServletResponse> result = doRequest(loginString, sessionCookie);
        ModelAndView modelView = result.getLeft();
        MockHttpServletResponse response = result.getRight();
        Assert.assertNull("modelView", modelView);
        Assert.assertNull("sessionCookie", response.getCookie(SESSION_COOKIE_NAME)); // no new session cookie is returned
        boolean ajaxRequest = false; // it is actually an ajax request but then TestContext would expect a session cookie to be returned
        validateAuthnSuccessResponse(response, Flow.AUTHZ_CODE, new Scope("openid"), false, ajaxRequest, STATE, NONCE);
    }

    @Test
    public void testLoginStringWithSessionCookieNonMatching() throws Exception {
        // if request has both a loginString and session cookie, then if the session cookie does not match, process the loginString
        String loginString = passwordLoginString();
        Cookie nonMatchingsessionCookie = new Cookie(SESSION_COOKIE_NAME, SESSION_ID + "_nonmatching");
        Pair<ModelAndView, MockHttpServletResponse> result = doRequest(loginString, nonMatchingsessionCookie);
        ModelAndView modelView = result.getLeft();
        MockHttpServletResponse response = result.getRight();
        Assert.assertNull("modelView", modelView);
        Assert.assertNotNull("sessionCookie", response.getCookie(SESSION_COOKIE_NAME)); // new session cookie is returned
        validateAuthnSuccessResponse(response, Flow.AUTHZ_CODE, new Scope("openid"), false, true, STATE, NONCE);
    }

    @Test
    public void testMissingLogin() throws Exception {
        Pair<ModelAndView, MockHttpServletResponse> result = doRequest(null /* loginString */, null /* sessionCookie */);
        ModelAndView modelView = result.getLeft();
        MockHttpServletResponse response = result.getRight();
        Assert.assertNotNull("modelView", modelView); // logon form should be served
        Assert.assertNull("sessionCookie", response.getCookie(SESSION_COOKIE_NAME));
        Assert.assertEquals("status", 200, response.getStatus());
    }

    private static void assertSuccessResponse(String loginString) throws Exception {
        Pair<ModelAndView, MockHttpServletResponse> result = doRequest(loginString, null /* sessionCookie */);
        ModelAndView modelView = result.getLeft();
        MockHttpServletResponse response = result.getRight();
        Assert.assertNull("modelView", modelView);
        Assert.assertNotNull("sessionCookie", response.getCookie(SESSION_COOKIE_NAME));
        validateAuthnSuccessResponse(response, Flow.AUTHZ_CODE, new Scope("openid"), false, true, STATE, NONCE);
    }

    private static void assertErrorResponse(
            String loginString,
            int expectedStatusCode,
            String expectedError,
            String expectedAuthzResponseHeaderPrefix) throws Exception {
        assertErrorResponse(loginString, expectedStatusCode, expectedError, expectedAuthzResponseHeaderPrefix, idmClient());
    }

    private static void assertErrorResponse(
            String loginString,
            int expectedStatusCode,
            String expectedError,
            String expectedAuthzResponseHeaderPrefix,
            IdmClient idmClient) throws Exception {
        Pair<ModelAndView, MockHttpServletResponse> result = doRequest(loginString, null /* sessionCookie */, idmClient);
        ModelAndView modelView = result.getLeft();
        MockHttpServletResponse response = result.getRight();
        Assert.assertNull("modelView", modelView);
        Assert.assertNull("sessionCookie", response.getCookie(SESSION_COOKIE_NAME));
        Assert.assertEquals("status", expectedStatusCode, response.getStatus());
        Object errorResponseHeader = response.getHeader("CastleError");
        Assert.assertNotNull("errorResponseHeader", errorResponseHeader);
        Assert.assertEquals("errorMessage", expectedError, response.getErrorMessage());

        if (expectedAuthzResponseHeaderPrefix != null) {
            Object authzResponseHeader = response.getHeader("CastleAuthorization");
            Assert.assertNotNull("authzResponseHeader", authzResponseHeader);
            Assert.assertTrue(
                    "expectedAuthzResponseHeaderPrefix",
                    authzResponseHeader.toString().startsWith(expectedAuthzResponseHeaderPrefix));
        }
    }

    private static Pair<ModelAndView, MockHttpServletResponse> doRequest(
            String loginString,
            Cookie sessionCookie) throws Exception {
        return doRequest(loginString, sessionCookie, idmClient());
    }

    private static Pair<ModelAndView, MockHttpServletResponse> doRequest(
            String loginString,
            Cookie sessionCookie,
            IdmClient idmClient) throws Exception {
        Map<String, String> queryParams = authnRequestParameters(Flow.AUTHZ_CODE);

        MockHttpServletRequest request;
        if (loginString != null) {
            Map<String, String> formParams = new HashMap<String, String>();
            formParams.put("CastleAuthorization", loginString);
            request = TestUtil.createPostRequestWithQueryString(formParams, queryParams);
        } else {
            request = TestUtil.createGetRequest(queryParams);
        }
        if (sessionCookie != null) {
            request.setCookies(sessionCookie);
        }

        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationController controller = authnController(idmClient);
        ModelAndView modelView = controller.authenticate(new ExtendedModelMap(), Locale.ENGLISH, request, response);
        return Pair.of(modelView, response);
    }
}