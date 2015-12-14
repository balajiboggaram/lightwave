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

import static com.vmware.identity.openidconnect.server.TestContext.CLIENT_ID;
import static com.vmware.identity.openidconnect.server.TestContext.CLIENT_PRIVATE_KEY;
import static com.vmware.identity.openidconnect.server.TestContext.SESSION_COOKIE_NAME;
import static com.vmware.identity.openidconnect.server.TestContext.SESSION_ID;
import static com.vmware.identity.openidconnect.server.TestContext.TENANT_PRIVATE_KEY;
import static com.vmware.identity.openidconnect.server.TestContext.clientAssertionClaims;
import static com.vmware.identity.openidconnect.server.TestContext.idTokenClaims;
import static com.vmware.identity.openidconnect.server.TestContext.idmClientBuilder;
import static com.vmware.identity.openidconnect.server.TestContext.initialize;
import static com.vmware.identity.openidconnect.server.TestContext.logoutController;
import static com.vmware.identity.openidconnect.server.TestContext.logoutRequestParameters;
import static com.vmware.identity.openidconnect.server.TestContext.sessionManager;
import static com.vmware.identity.openidconnect.server.TestContext.validateLogoutErrorResponse;
import static com.vmware.identity.openidconnect.server.TestContext.validateLogoutSuccessResponse;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.vmware.identity.openidconnect.common.SessionID;

/**
 * @author Yehia Zayour
 */
public class LogoutControllerTest {
    @BeforeClass
    public static void setup() throws Exception {
        initialize();
    }

    @Test
    public void testLogoutUsingPost() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        MockHttpServletResponse response = doRequest(params, (SessionID) null, logoutController(), true /* isPost */);
        validateLogoutSuccessResponse(
                response,
                true /* redirect */,
                true /* withState */,
                false /* expectingLogoutUriLinks */,
                false /* expectingSessionCookie */);
    }

    @Test
    public void testLogoutWithRedirectWithState() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        assertSuccessResponse(
                params,
                true /* redirect */,
                true /* withState */,
                false /* expectingLogoutUriLinks */,
                false /* expectingSessionCookie */);
    }

    @Test
    public void testLogoutWithRedirectWithoutState() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.remove("state");
        assertSuccessResponse(
                params,
                true /* redirect */,
                false /* withState */,
                false /* expectingLogoutUriLinks */,
                false /* expectingSessionCookie */);
    }

    @Test
    public void testLogoutWithoutRedirect() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.remove("post_logout_redirect_uri");
        params.remove("state");
        assertSuccessResponse(
                params,
                false /* redirect */,
                false /* withState */,
                false /* expectingLogoutUriLinks */,
                false /* expectingSessionCookie */);
    }

    @Test
    public void testLogoutWithMatchingSessionCookie() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        SessionID sessionId = new SessionID(SESSION_ID);
        SessionManager sessionManager = sessionManager();
        LogoutController controller = logoutController();
        controller.setSessionManager(sessionManager);
        Assert.assertTrue("sessionManager.get(sessionId)!=null", sessionManager.get(sessionId) != null);
        assertSuccessResponse(
                params,
                true /* redirect */,
                true /* withState */,
                true /* expectingLogoutUriLinks */,
                true /* expectingSessionCookie */,
                sessionId,
                controller);
        Assert.assertTrue("sessionManager.get(sessionId)==null", sessionManager.get(sessionId) == null);
    }

    @Test
    public void testLogoutWithNonMatchingSessionCookie() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        SessionID sessionIdMatching = new SessionID(SESSION_ID);
        SessionID sessionIdNonMatching = new SessionID(SESSION_ID + "non_matching");
        SessionManager sessionManager = sessionManager();
        LogoutController controller = logoutController();
        controller.setSessionManager(sessionManager);
        Assert.assertTrue("sessionManager.get(sessionId)!=null", sessionManager.get(sessionIdMatching) != null);
        assertSuccessResponse(
                params,
                true /* redirect */,
                true /* withState */,
                false /* expectingLogoutUriLinks */,
                true /* expectingSessionCookie */,
                sessionIdNonMatching,
                controller);
        Assert.assertTrue("sessionManager.get(sessionId)!=null", sessionManager.get(sessionIdMatching) != null);
    }

    @Test
    public void testLogoutWithoutCorrelationId() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.remove("correlation_id");
        assertSuccessResponse(
                params,
                true /* redirect */,
                true /* withState */,
                false /* expectingLogoutUriLinks */,
                false /* expectingSessionCookie */);
    }

    @Test
    public void testLogoutClientAssertionNotRequired() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.remove("client_assertion");

        IdmClient idmClient = idmClientBuilder().tokenEndpointAuthMethod("none").clientCertSubjectDN(null).build();
        LogoutController controller = logoutController(idmClient);

        assertSuccessResponse(
                params,
                true /* redirect */,
                true /* withState */,
                false /* expectingLogoutUriLinks */,
                false /* expectingSessionCookie */,
                (SessionID) null,
                controller);
    }

    @Test
    public void testLogoutClientAssertionMissing() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.remove("client_assertion");
        assertErrorResponse(params, "invalid_client: client_assertion parameter is required since client has registered a cert");
    }

    @Test
    public void testLogoutClientAssertionInvalidAudience() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet clientAssertionClaims = clientAssertionClaims();
        clientAssertionClaims.setAudience(clientAssertionClaims.getAudience() + "non_matching");
        params.put("client_assertion", Shared.sign(clientAssertionClaims, CLIENT_PRIVATE_KEY).serialize());
        assertErrorResponse(params, "invalid_client: assertion audience does not match request URL");
    }

    @Test
    public void testLogoutClientAssertionStale() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet clientAssertionClaims = clientAssertionClaims();
        Date issuedAt = new Date(clientAssertionClaims.getIssueTime().getTime() - (5 * 60 * 1000L)); // issued 5 mins ago
        clientAssertionClaims.setIssueTime(issuedAt);
        params.put("client_assertion", Shared.sign(clientAssertionClaims, CLIENT_PRIVATE_KEY).serialize());
        assertErrorResponse(params, "invalid_client: stale_client_assertion");
    }

    @Test
    public void testNonExistentTenant() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        MockHttpServletRequest request = TestUtil.createPostRequest(params);
        MockHttpServletResponse response = new MockHttpServletResponse();

        LogoutController controller = logoutController();
        controller.logout(request, response, "non_matching_tenant");

        String expectedErrorMessage = "invalid_request: non-existent tenant";
        validateLogoutErrorResponse(response, expectedErrorMessage);
    }

    @Test
    public void testUnregisteredClient() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        IdmClient idmClient = idmClientBuilder().clientId(CLIENT_ID + "non_matching").build();
        LogoutController controller = logoutController(idmClient);
        assertErrorResponse(params, "invalid_client: unregistered client", null, controller);
    }

    @Test
    public void testUnregisteredRedirectUri() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.put("post_logout_redirect_uri", params.get("post_logout_redirect_uri") + "non_matching");
        String expectedErrorMessage = "invalid_request: unregistered post_logout_redirect_uri";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testInvalidRedirectUri() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.put("post_logout_redirect_uri", "http://a.com/redirect"); // should be https
        String expectedErrorMessage = "invalid_request: invalid post_logout_redirect_uri";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintMissing() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.remove("id_token_hint");
        String expectedErrorMessage = "invalid_request: Missing \"id_token_hint\" parameter";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintInvalid() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        params.put("id_token_hint", "invalid_id_token_hint_jwt");
        String expectedErrorMessage = "invalid_request: Invalid ID token hint: Invalid JWT serialization: Missing dot delimiter(s)";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintPlainJwt() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        PlainJWT idToken = new PlainJWT(claimsSet);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token_hint must be a signed jwt";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintInvalidTokenClass() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setClaim("token_class", true); // token_class should be a string claim
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token has non-string token_class claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintIncorrectTokenClass() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setClaim("token_class", "access_token"); // should be id_token
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token has incorrect token_class claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintMissingTokenClass() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setClaim("token_class", null);
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token is missing token_class claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintMissingIssuer() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setIssuer(null);
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token is missing iss (issuer) claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintMissingSubject() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setSubject(null);
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token is missing sub (subject) claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintMissingAudience() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setAudience((String) null);
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token is missing aud (audience) claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintMissingIssuedAt() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setIssueTime(null);
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token is missing iat (issued at) claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintMissingExpiration() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setExpirationTime(null);
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token is missing exp (expiration) claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintMissingJwtId() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setJWTID(null);
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token is missing jti (jwt id) claim";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintIncorrectIssuer() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setIssuer(claimsSet.getIssuer() + "non_matching");
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token has incorrect issuer";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintNonMatchingSubject() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        claimsSet.setSubject(claimsSet.getSubject() + "non_matching");
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token subject does not match the session user";
        assertErrorResponse(params, expectedErrorMessage, new SessionID(SESSION_ID), logoutController());
    }

    @Test
    public void testIdTokenHintInvalidAudience() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        List<String> audience = new ArrayList<String>();
        audience.add("aud1");
        audience.add("aud2");
        claimsSet.setAudience(audience);
        SignedJWT idToken = Shared.sign(claimsSet, TENANT_PRIVATE_KEY);
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token must have a single audience value containing the client_id";
        assertErrorResponse(params, expectedErrorMessage);
    }

    @Test
    public void testIdTokenHintInvalidSignature() throws Exception {
        Map<String, String> params = logoutRequestParameters();
        JWTClaimsSet claimsSet = idTokenClaims();
        SignedJWT idToken = Shared.sign(claimsSet, CLIENT_PRIVATE_KEY); // should be signed using server private key
        params.put("id_token_hint", idToken.serialize());
        String expectedErrorMessage = "invalid_request: id_token has an invalid signature";
        assertErrorResponse(params, expectedErrorMessage);
    }

    private static void assertSuccessResponse(
            Map<String, String> params,
            boolean redirect,
            boolean withState,
            boolean expectingLogoutUriLinks,
            boolean expectingSessionCookie) throws Exception {
        assertSuccessResponse(params, redirect, withState, expectingLogoutUriLinks, expectingSessionCookie, null, logoutController());
    }

    private static void assertSuccessResponse(
            Map<String, String> params,
            boolean redirect,
            boolean withState,
            boolean expectingLogoutUriLinks,
            boolean expectingSessionCookie,
            SessionID sessionId,
            LogoutController controller) throws Exception {
        MockHttpServletResponse response = doRequest(params, sessionId, controller, false /* isPost */);
        validateLogoutSuccessResponse(
                response,
                redirect,
                withState,
                expectingLogoutUriLinks,
                expectingSessionCookie);
    }

    private static void assertErrorResponse(
            Map<String, String> params,
            String expectedErrorMessage) throws Exception {
        assertErrorResponse(params, expectedErrorMessage, null, logoutController());
    }

    private static void assertErrorResponse(
            Map<String, String> params,
            String expectedErrorMessage,
            SessionID sessionId,
            LogoutController controller) throws Exception {
        MockHttpServletResponse response = doRequest(params, sessionId, controller, false /* isPost */);
        validateLogoutErrorResponse(response, expectedErrorMessage);
    }

    private static MockHttpServletResponse doRequest(
            Map<String, String> params,
            SessionID sessionId,
            LogoutController controller,
            boolean isPost) throws Exception {
        MockHttpServletRequest request = isPost ? TestUtil.createPostRequest(params) : TestUtil.createGetRequest(params);
        if (sessionId != null) {
            request.setCookies(new Cookie(SESSION_COOKIE_NAME, sessionId.getValue()));
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        controller.logout(request, response);
        return response;
    }
}