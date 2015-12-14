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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.Cookie;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mock.web.MockHttpServletResponse;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.ResponseMode;
import com.vmware.identity.idm.AuthnPolicy;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.ResourceServer;
import com.vmware.identity.openidconnect.common.AuthenticationRequest;
import com.vmware.identity.openidconnect.common.SessionID;

/**
 * @author Yehia Zayour
 */
public class TestContext {
    public static final String TENANT_NAME = "tenant_name";
    public static final String ISSUER = "https://psc.vmware.com/openidconnect/" + TENANT_NAME;
    public static final String SCOPE_VALUE_RSX = "rs_x";
    public static final String CLIENT_ID = "_client_id_xyz_";
    public static final String STATE = "_state_xyz_";
    public static final String LOGOUT_STATE = "_logout_state_xyz_";
    public static final String NONCE = "_nonce_xyz_";
    public static final String AUTHZ_CODE = "_authz_code_xyz_";
    public static final String USERNAME = "_username_xyz_";
    public static final String PASSWORD = "_password_xyz_";
    public static final String SESSION_ID = "_session_id_xyz_";
    public static final String SOLUTION_USERNAME = "_solution_username_xyz_";
    public static final String CLIENT_CERT_SUBJECT_DN = "OU=abc,C=US,DC=local,DC=vsphere,CN=_solution_username_xyz_";
    public static final String GSS_CONTEXT_ID = "_context_id_xyz_";
    public static final String ADMIN_SERVER_ROLE = "GuestUser";
    public static final PersonUser PERSON_USER = new PersonUser(new PrincipalId(USERNAME, TENANT_NAME), TENANT_NAME);
    public static final Set<String> GROUP_FILTER_RS_X           = new HashSet<String>(Arrays.asList(                "o\\c", "o\\d"));
    public static final Set<String> GROUP_FILTER_RS_Y           = new HashSet<String>(Arrays.asList(        "o\\b", "o\\c"        ));
    public static final Set<String> GROUP_MEMBERSHIP            = new HashSet<String>(Arrays.asList("o\\A", "o\\B", "o\\C"        ));
    public static final Set<String> GROUP_MEMBERSHIP_FILTERED   = new HashSet<String>(Arrays.asList(        "o\\b", "o\\c"        ));
    public static URI AUTHZ_ENDPOINT_URI;
    public static URI TOKEN_ENDPOINT_URI;
    public static URI LOGOUT_ENDPOINT_URI;
    public static URI REDIRECT_URI;
    public static URI POST_LOGOUT_REDIRECT_URI;
    public static URI LOGOUT_URI;
    public static SolutionUser SOLUTION_USER;
    public static String SESSION_COOKIE_NAME;
    public static RSAPrivateKey TENANT_PRIVATE_KEY;
    public static RSAPublicKey TENANT_PUBLIC_KEY;
    public static X509Certificate TENANT_CERT;
    public static RSAPrivateKey CLIENT_PRIVATE_KEY;
    public static RSAPublicKey CLIENT_PUBLIC_KEY;
    public static X509Certificate CLIENT_CERT;

    public static void initialize() throws Exception {
        AUTHZ_ENDPOINT_URI          = new URI("https://identity.vmware.com/authz");
        TOKEN_ENDPOINT_URI          = new URI("https://identity.vmware.com/token");
        LOGOUT_ENDPOINT_URI         = new URI("https://identity.vmware.com/logout");
        REDIRECT_URI                = new URI("https://vcenter-server.com/relying-party/redirect");
        POST_LOGOUT_REDIRECT_URI    = new URI("https://vcenter-server.com/relying-party/post-logout-redirect");
        LOGOUT_URI                  = new URI("https://vcenter-server.com/relying-party/logout");

        SESSION_COOKIE_NAME = Shared.getSessionCookieName(TENANT_NAME);

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyGenerator.initialize(1024, new SecureRandom());

        KeyPair kp = keyGenerator.genKeyPair();
        TENANT_PRIVATE_KEY = (RSAPrivateKey) kp.getPrivate();
        TENANT_PUBLIC_KEY = (RSAPublicKey) kp.getPublic();
        TENANT_CERT = TestUtil.generateCertificate(kp, "CN=server");

        kp = keyGenerator.genKeyPair();
        CLIENT_PRIVATE_KEY = (RSAPrivateKey) kp.getPrivate();
        CLIENT_PUBLIC_KEY = (RSAPublicKey) kp.getPublic();
        CLIENT_CERT = TestUtil.generateCertificate(kp, CLIENT_CERT_SUBJECT_DN);

        SOLUTION_USER = new SolutionUser(
                new PrincipalId(SOLUTION_USERNAME, TENANT_NAME),
                TENANT_NAME,
                CLIENT_CERT);
    }

    public static AuthenticationController authnController() {
        return authnController(idmClient());
    }

    public static AuthenticationController authnController(IdmClient idmClient) {
        return new AuthenticationController(idmClient, authzCodeManager(), sessionManager(), messageSource());
    }

    public static TokenController tokenController() {
        return tokenController(idmClient());
    }

    public static TokenController tokenController(IdmClient idmClient) {
        return new TokenController(idmClient, authzCodeManager());
    }

    public static LogoutController logoutController() {
        return logoutController(idmClient());
    }

    public static LogoutController logoutController(IdmClient idmClient) {
        return new LogoutController(idmClient, sessionManager());
    }

    public static MockIdmClient idmClient() {
        return idmClientBuilder().build();
    }

    public static MockIdmClient.Builder idmClientBuilder() {
        long tokenBearerLifetimeMs        = 1000L * 60 * 5;
        long tokenHokLifetimeMs           = 1000L * 60 * 60 * 2;
        long refreshTokenBearerLifetimeMs = 1000L * 60 * 60 * 6;
        long refreshTokenHokLifetimeMs    = 1000L * 60 * 60 * 24 * 30;
        long clockToleranceMs             = 0L;

        boolean allowPasswordAuthn = true;
        boolean allowWindowsSessionAuthn = true;
        boolean allowSmartCardAuthn = false;

        Map<String, ResourceServer> resourceServerMap = new HashMap<String, ResourceServer>();
        resourceServerMap.put("rs_x", new ResourceServer.Builder("rs_x").groupFilter(GROUP_FILTER_RS_X).build());
        resourceServerMap.put("rs_y", new ResourceServer.Builder("rs_y").groupFilter(GROUP_FILTER_RS_Y).build());

        return new MockIdmClient.Builder().
                tenantName(TENANT_NAME).
                tenantPrivateKey(TENANT_PRIVATE_KEY).
                tenantCertificate(TENANT_CERT).
                authnPolicy(new AuthnPolicy(allowPasswordAuthn, allowWindowsSessionAuthn, allowSmartCardAuthn, null /* ClientCertPolicy */)).
                issuer(ISSUER).

                clientId(CLIENT_ID).
                redirectUri(REDIRECT_URI.toString()).
                postLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI.toString()).
                logoutUri(LOGOUT_URI.toString()).
                clientCertSubjectDN(CLIENT_CERT_SUBJECT_DN).
                clientCertificate(CLIENT_CERT).
                tokenEndpointAuthMethod("private_key_jwt").

                username(USERNAME).
                password(PASSWORD).
                gssContextId(GSS_CONTEXT_ID).
                personUserEnabled(true).

                solutionUsername(SOLUTION_USERNAME).
                solutionUserEnabled(true).

                maxBearerTokenLifetime(tokenBearerLifetimeMs).
                maxHoKTokenLifetime(tokenHokLifetimeMs).
                maxBearerRefreshTokenLifetime(refreshTokenBearerLifetimeMs).
                maxHoKRefreshTokenLifetime(refreshTokenHokLifetimeMs).
                clockTolerance(clockToleranceMs).

                systemGroupMembership(Collections.singleton("ActAsUsers")).
                groupMembership(GROUP_MEMBERSHIP).
                resourceServerMap(resourceServerMap);
    }

    public static AuthorizationCodeManager authzCodeManager() {
        AuthorizationCodeManager authzCodeManager = new AuthorizationCodeManager();

        AuthenticationRequest originalAuthnRequest = new AuthenticationRequest(
                AUTHZ_ENDPOINT_URI,
                new ResponseType(ResponseType.Value.CODE),
                ResponseMode.FORM_POST,
                new ClientID(CLIENT_ID),
                REDIRECT_URI,
                new Scope("openid"),
                new State(STATE),
                new Nonce(NONCE),
                null /* clientAssertion */,
                null /* correlationId */);
        authzCodeManager.add(
                new AuthorizationCode(AUTHZ_CODE),
                PERSON_USER,
                new SessionID(SESSION_ID),
                originalAuthnRequest);

        return authzCodeManager;
    }

    public static SessionManager sessionManager() {
        SessionManager sessionManager = new SessionManager();

        ClientInfo clientInfo = new ClientInfo(
                new ClientID(CLIENT_ID),
                Collections.singleton(REDIRECT_URI),
                Collections.singleton(POST_LOGOUT_REDIRECT_URI),
                LOGOUT_URI,
                CLIENT_CERT_SUBJECT_DN);

        sessionManager.add(new SessionID(SESSION_ID), PERSON_USER, clientInfo);
        return sessionManager;
    }

    public static ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        return messageSource;
    }

    public static JWTClaimsSet idTokenClaims() {
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setClaim("token_class", "id_token");
        claimsSet.setClaim("token_type", "Bearer");
        claimsSet.setJWTID((new JWTID()).toString());
        claimsSet.setIssuer(ISSUER);
        claimsSet.setSubject(PERSON_USER.getSubject().getValue());
        claimsSet.setAudience(CLIENT_ID);
        claimsSet.setIssueTime(now);
        claimsSet.setExpirationTime(new Date(now.getTime() + 2 * 60 * 1000L));
        return claimsSet;
    }

    public static JWTClaimsSet refreshTokenClaims() {
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setClaim("token_class", "refresh_token");
        claimsSet.setClaim("token_type", "Bearer");
        claimsSet.setJWTID((new JWTID()).toString());
        claimsSet.setIssuer(ISSUER);
        claimsSet.setSubject(PERSON_USER.getSubject().getValue());
        claimsSet.setAudience(PERSON_USER.getSubject().getValue());
        claimsSet.setIssueTime(now);
        claimsSet.setExpirationTime(new Date(now.getTime() + 2 * 60 * 1000L));
        claimsSet.setClaim("tenant", TENANT_NAME);
        claimsSet.setClaim("scope", "openid");
        claimsSet.setClaim("sid", SESSION_ID);
        return claimsSet;
    }

    public static JWTClaimsSet refreshTokenClaimsSltn() {
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setClaim("token_class", "refresh_token");
        claimsSet.setClaim("token_type", "hotk-pk");
        claimsSet.setJWTID((new JWTID()).toString());
        claimsSet.setIssuer(ISSUER);
        claimsSet.setSubject(PERSON_USER.getSubject().getValue());
        claimsSet.setAudience(SOLUTION_USER.getSubject().getValue());
        claimsSet.setIssueTime(now);
        claimsSet.setExpirationTime(new Date(now.getTime() + 2 * 60 * 1000L));
        claimsSet.setClaim("tenant", TENANT_NAME);
        claimsSet.setClaim("scope", "openid");
        claimsSet.setClaim("sid", SESSION_ID);
        claimsSet.setClaim("act_as", SOLUTION_USER.getSubject().getValue());
        return claimsSet;
    }

    public static JWTClaimsSet refreshTokenClaimsClient() {
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setClaim("token_class", "refresh_token");
        claimsSet.setClaim("token_type", "hotk-pk");
        claimsSet.setJWTID((new JWTID()).toString());
        claimsSet.setIssuer(ISSUER);
        claimsSet.setSubject(PERSON_USER.getSubject().getValue());
        claimsSet.setAudience(CLIENT_ID);
        claimsSet.setIssueTime(now);
        claimsSet.setExpirationTime(new Date(now.getTime() + 2 * 60 * 1000L));
        claimsSet.setClaim("tenant", TENANT_NAME);
        claimsSet.setClaim("scope", "openid");
        claimsSet.setClaim("sid", SESSION_ID);
        claimsSet.setClaim("act_as", SOLUTION_USER.getSubject().getValue());
        claimsSet.setClaim("client_id", CLIENT_ID);
        return claimsSet;
    }

    public static JWTClaimsSet sltnAssertionClaims() {
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setClaim("token_class", "solution_assertion");
        claimsSet.setClaim("token_type", "Bearer");
        claimsSet.setJWTID((new JWTID()).toString());
        claimsSet.setIssuer(CLIENT_CERT_SUBJECT_DN);
        claimsSet.setSubject(CLIENT_CERT_SUBJECT_DN);
        claimsSet.setAudience("https://localhost");
        claimsSet.setIssueTime(now);
        claimsSet.setExpirationTime(new Date(now.getTime() + 356 * 24 * 60 * 60 * 1000L));
        return claimsSet;
    }

    public static JWTClaimsSet clientAssertionClaims() {
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setClaim("token_class", "client_assertion");
        claimsSet.setClaim("token_type", "Bearer");
        claimsSet.setJWTID((new JWTID()).toString());
        claimsSet.setIssuer(CLIENT_ID);
        claimsSet.setSubject(CLIENT_ID);
        claimsSet.setAudience("https://localhost");
        claimsSet.setIssueTime(now);
        claimsSet.setExpirationTime(new Date(now.getTime() + 2 * 60 * 1000L));
        return claimsSet;
    }

    public static String passwordLoginString() {
        return passwordLoginString(USERNAME, PASSWORD);
    }

    public static String passwordLoginString(String username, String password) {
        String unp = username + ":" + password;
        String unp64 = Base64.encode(unp).toString();
        return "Basic " + unp64;
    }

    public static String gssLoginString() {
        return gssLoginString(GSS_CONTEXT_ID);
    }

    public static String gssLoginString(String contextId) {
        return String.format("Negotiate %s _gss_ticket__xyz_", contextId);
    }

    public static Map<String, String> authnRequestParameters(Flow flow) throws Exception {
        return authnRequestParameters(flow, "form_post");
    }

    public static Map<String, String> authnRequestParameters(Flow flow, String responseMode) throws Exception {
        assert flow.isAuthzEndpointFlow();

        String responseType;
        switch (flow) {
            case AUTHZ_CODE:
                responseType = "code";
                break;
            case IMPLICIT:
                responseType = "id_token token";
                break;
            case IMPLICIT_ID_TOKEN_ONLY:
                responseType = "id_token";
                break;
            default:
                throw new IllegalArgumentException("unrecognized flow value " + flow.toString());
        }

        Map<String, String> params = new HashMap<String, String>();
        params.put("response_type", responseType);
        params.put("response_mode", responseMode);
        params.put("client_id", CLIENT_ID);
        params.put("redirect_uri", REDIRECT_URI.toString());
        params.put("scope", "openid");
        params.put("state", STATE);
        params.put("nonce", NONCE);
        params.put("client_assertion", Shared.sign(clientAssertionClaims(), CLIENT_PRIVATE_KEY).serialize());
        return params;
    }

    public static Map<String, String> tokenRequestParameters(Flow flow) throws Exception {
        assert flow.isTokenEndpointFlow();
        assert flow != Flow.AUTHZ_CODE && flow != Flow.CLIENT_CREDS && flow != Flow.SOLUTION_USER_CREDS;
        Map<String, String> params = tokenRequestAuthzGrantAndScope(flow, refreshTokenClaims());
        return params;
    }

    public static Map<String, String> tokenRequestParametersSltn(Flow flow) throws Exception {
        return tokenRequestParametersSltn(flow, sltnAssertionClaims());
    }

    public static Map<String, String> tokenRequestParametersSltn(Flow flow, JWTClaimsSet sltnAssertionClaims) throws Exception {
        assert flow.isTokenEndpointFlow();
        assert flow != Flow.AUTHZ_CODE && flow != Flow.CLIENT_CREDS;
        Map<String, String> params = tokenRequestAuthzGrantAndScope(flow, refreshTokenClaimsSltn());
        params.put("solution_assertion", Shared.sign(sltnAssertionClaims, CLIENT_PRIVATE_KEY).serialize());
        return params;
    }

    public static Map<String, String> tokenRequestParametersClient(Flow flow) throws Exception {
        return tokenRequestParametersClient(flow, clientAssertionClaims());
    }

    public static Map<String, String> tokenRequestParametersClient(Flow flow, JWTClaimsSet clientAssertionClaims) throws Exception {
        assert flow.isTokenEndpointFlow();
        assert flow != Flow.SOLUTION_USER_CREDS;
        Map<String, String> params = tokenRequestAuthzGrantAndScope(flow, refreshTokenClaimsClient());
        params.put("client_assertion", Shared.sign(clientAssertionClaims, CLIENT_PRIVATE_KEY).serialize());
        params.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        return params;
    }

    public static Map<String, String> logoutRequestParameters() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("id_token_hint", Shared.sign(idTokenClaims(), TENANT_PRIVATE_KEY).serialize());
        params.put("post_logout_redirect_uri", POST_LOGOUT_REDIRECT_URI.toString());
        params.put("state", LOGOUT_STATE);
        params.put("client_assertion", Shared.sign(clientAssertionClaims(), CLIENT_PRIVATE_KEY).serialize());
        return params;
    }

    public static AuthnResponse validateAuthnSuccessResponse(
            MockHttpServletResponse response,
            Flow        flow,
            Scope       scope,
            boolean     redirectResponseMode,
            boolean     ajaxRequest,
            String      expectedState,
            String      expectedNonce) throws Exception {
        return validateAuthnSuccessResponse(
                response,
                flow,
                scope,
                redirectResponseMode,
                ajaxRequest,
                expectedState,
                expectedNonce,
                GROUP_MEMBERSHIP,
                GROUP_MEMBERSHIP,
                ADMIN_SERVER_ROLE);
    }

    public static AuthnResponse validateAuthnSuccessResponse(
            MockHttpServletResponse response,
            Flow        flow,
            Scope       scope,
            boolean     redirectResponseMode,
            boolean     ajaxRequest,
            String      expectedState,
            String      expectedNonce,
            Set<String> expectedIdTokenGroups,
            Set<String> expectedAccessTokenGroups,
            String      expectedAdminServerRole) throws Exception {
        assert flow.isAuthzEndpointFlow();

        assertEquals("status", (redirectResponseMode && !ajaxRequest) ? 302 : 200, response.getStatus());
        assertEquals("redirectTarget", REDIRECT_URI.toString(), extractAuthnResponseTarget(flow, response, redirectResponseMode, ajaxRequest));
        assertNull("error", extractAuthnResponseParameter(flow, response, "error", redirectResponseMode, ajaxRequest));
        assertEquals("state", expectedState, extractAuthnResponseParameter(flow, response, "state", redirectResponseMode, ajaxRequest));
        assertNull("refresh_token", extractAuthnResponseParameter(flow, response, "refresh_token", redirectResponseMode, ajaxRequest));

        String authzCode = extractAuthnResponseParameter(flow, response, "code", redirectResponseMode, ajaxRequest);
        String idToken = null;
        String accessToken = null;
        if (flow == Flow.AUTHZ_CODE) {
            assertNotNull("authzCode", authzCode);
        } else if (flow.isImplicit()) {
            assertNull("authzCode", authzCode);
            Cookie sessionCookie = response.getCookie(Shared.getSessionCookieName(TENANT_NAME));
            String expectedSessionId = (sessionCookie != null) ? sessionCookie.getValue() : SESSION_ID;
            idToken = extractAuthnResponseParameter(flow, response, "id_token", redirectResponseMode, ajaxRequest);
            validateToken(
                    "id_token",
                    idToken,
                    flow,
                    scope,
                    false /* wSltnAssertion */,
                    false /* wClientAssertion */,
                    expectedNonce,
                    expectedSessionId,
                    expectedIdTokenGroups,
                    expectedAccessTokenGroups,
                    expectedAdminServerRole);
            if (flow == Flow.IMPLICIT) {
                assertEquals("token_type==Bearer", "Bearer", extractAuthnResponseParameter(flow, response, "token_type", redirectResponseMode, ajaxRequest));
                assertEquals("expires_in==300", "300", extractAuthnResponseParameter(flow, response, "expires_in", redirectResponseMode, ajaxRequest));
                accessToken = extractAuthnResponseParameter(flow, response, "access_token", redirectResponseMode, ajaxRequest);
                validateToken(
                        "access_token",
                        accessToken,
                        flow,
                        scope,
                        false /* wSltnAssertion */,
                        false /* wClientAssertion */,
                        expectedNonce,
                        expectedSessionId,
                        expectedIdTokenGroups,
                        expectedAccessTokenGroups,
                        expectedAdminServerRole);
            }
            if (flow == Flow.IMPLICIT_ID_TOKEN_ONLY) {
                assertNull("access_token", extractAuthnResponseParameter(flow, response, "access_token", redirectResponseMode, ajaxRequest));
            }
        }

        Cookie sessionCookie = response.getCookie(SESSION_COOKIE_NAME);
        if (ajaxRequest) {
            assertNotNull("sessionCookie", sessionCookie);
        } else {
            assertNull("sessionCookie", sessionCookie);
        }

        return new AuthnResponse(idToken, accessToken, authzCode);
    }

    public static void validateAuthnErrorResponse(
            MockHttpServletResponse response,
            Flow        flow,
            boolean     redirectResponseMode,
            boolean     ajaxRequest,
            String      expectedError,
            String      expectedErrorDescription) throws Exception {
        assert flow.isAuthzEndpointFlow();

        assertEquals("status", (redirectResponseMode && !ajaxRequest) ? 302 : 200, response.getStatus());
        assertEquals("redirectTarget", REDIRECT_URI.toString(), extractAuthnResponseTarget(flow, response, redirectResponseMode, ajaxRequest));
        assertEquals("state", STATE, extractAuthnResponseParameter(flow, response, "state", redirectResponseMode, ajaxRequest));
        assertEquals("error", expectedError, extractAuthnResponseParameter(flow, response, "error", redirectResponseMode, ajaxRequest));
        assertEquals(
                "error_description",
                expectedErrorDescription,
                extractAuthnResponseParameter(flow, response, "error_description", redirectResponseMode, ajaxRequest));
        assertNull("sessionCookie", response.getCookie(SESSION_COOKIE_NAME));
    }

    public static TokenResponse validateTokenSuccessResponse(
            MockHttpServletResponse response,
            Flow        flow,
            Scope       scope,
            boolean     wSltnAssertion,
            boolean     wClientAssertion,
            String      expectedNonce) throws Exception {
        return validateTokenSuccessResponse(
                response,
                flow,
                scope,
                wSltnAssertion,
                wClientAssertion,
                expectedNonce,
                GROUP_MEMBERSHIP,
                GROUP_MEMBERSHIP,
                ADMIN_SERVER_ROLE);
    }

    public static TokenResponse validateTokenSuccessResponse(
            MockHttpServletResponse response,
            Flow        flow,
            Scope       scope,
            boolean     wSltnAssertion,
            boolean     wClientAssertion,
            String      expectedNonce,
            Set<String> expectedIdTokenGroups,
            Set<String> expectedAccessTokenGroups,
            String      expectedAdminServerRole) throws Exception {
        assert flow.isTokenEndpointFlow();

        JSONParser jsonParser = new JSONParser(JSONParser.DEFAULT_PERMISSIVE_MODE);
        JSONObject jsonObject = (JSONObject) jsonParser.parse(response.getContentAsString());
        String idToken      = (String)  jsonObject.get("id_token");
        String accessToken  = (String)  jsonObject.get("access_token");
        String refreshToken = (String)  jsonObject.get("refresh_token");
        String tokenType    = (String)  jsonObject.get("token_type");
        Integer expiresIn   = (Integer) jsonObject.get("expires_in");

        assertEquals("token_type", (wSltnAssertion || wClientAssertion) ? "hotk-pk" : "Bearer", tokenType);
        assertEquals("expires_in", (wSltnAssertion || wClientAssertion) ? 7200 : 300, expiresIn.intValue());

        validateToken(
                "id_token",
                idToken,
                flow,
                scope,
                wSltnAssertion,
                wClientAssertion,
                expectedNonce,
                null /* expectedSessionId */,
                expectedIdTokenGroups,
                expectedAccessTokenGroups,
                expectedAdminServerRole);

        validateToken(
                "access_token",
                accessToken,
                flow,
                scope,
                wSltnAssertion,
                wClientAssertion,
                expectedNonce,
                null /* expectedSessionId */,
                expectedIdTokenGroups,
                expectedAccessTokenGroups,
                expectedAdminServerRole);

        boolean refreshTokenShouldExist =
                scope.contains("offline_access") &&
                (flow == Flow.AUTHZ_CODE || flow == Flow.PASSWORD || flow == Flow.GSS_TICKET);
        assertEquals("refreshTokenShouldExist", refreshTokenShouldExist, refreshToken != null);
        if (refreshTokenShouldExist) {
            validateToken(
                    "refresh_token",
                    refreshToken,
                    flow,
                    scope,
                    wSltnAssertion,
                    wClientAssertion,
                    expectedNonce,
                    null /* expectedSessionId */,
                    expectedIdTokenGroups,
                    expectedAccessTokenGroups,
                    expectedAdminServerRole);
        }

        return new TokenResponse(idToken, accessToken, refreshToken);
    }

    public static void validateTokenErrorResponse(
            MockHttpServletResponse response,
            Flow        flow,
            String      expectedError,
            String      expectedErrorDescription) throws Exception {
        assert flow.isTokenEndpointFlow();

        JSONParser jsonParser = new JSONParser(JSONParser.DEFAULT_PERMISSIVE_MODE);
        JSONObject jsonObject = (JSONObject) jsonParser.parse(response.getContentAsString());
        String error = (String) jsonObject.get("error");
        String errorDescription = (String) jsonObject.get("error_description");

        assertEquals("error", expectedError, error);
        assertEquals("error_description", expectedErrorDescription, errorDescription);
    }

    public static void validateLogoutSuccessResponse(
            MockHttpServletResponse response,
            boolean     redirect,
            boolean     withState,
            boolean     expectingLogoutUriLinks,
            boolean     expectingSessionCookie) throws Exception {
        validateLogoutSuccessResponse(
                response,
                redirect,
                withState,
                expectingLogoutUriLinks,
                expectingSessionCookie,
                SESSION_ID,
                new URI[0]);
    }

    public static void validateLogoutSuccessResponse(
            MockHttpServletResponse response,
            boolean     redirect,
            boolean     withState,
            boolean     expectingLogoutUriLinks,
            boolean     expectingSessionCookie,
            String      expectedSessionId,
            URI[]       expectedLogoutUris) throws Exception {
        assertNull("response.getErrorMessage", response.getErrorMessage());
        assertEquals("response.getStatus", 200, response.getStatus());

        String expectedRedirectTarget;
        if (redirect) {
            if (withState) {
                expectedRedirectTarget = String.format("%s?state=%s", POST_LOGOUT_REDIRECT_URI.toString(), LOGOUT_STATE);
            } else {
                expectedRedirectTarget = POST_LOGOUT_REDIRECT_URI.toString();
            }
        } else {
            expectedRedirectTarget = "";
        }
        String redirectTarget = TestUtil.extractString(response, "var postLogoutRedirectUriWithState = \"", "\"");
        assertEquals("postLogoutRedirectUriWithState", expectedRedirectTarget, redirectTarget);

        String logoutUriLinks = TestUtil.extractString(response, "<!-- logoutUriLinks --> ", " <!-- logoutUriLinks -->");
        if (expectingLogoutUriLinks) {
            int expectedLength = 0;
            for (URI expectedLogoutUri : expectedLogoutUris) {
                String expectedLogoutUriWithSid = String.format("%s?sid=%s", expectedLogoutUri, expectedSessionId);
                String expectedLogoutUriLink = String.format("<iframe src=\"%s\">", expectedLogoutUriWithSid);
                assertTrue("logoutUriLinks.contains(expectedLogoutUriLink)", logoutUriLinks.contains(expectedLogoutUriLink));
                expectedLength += expectedLogoutUriLink.length();
            }
            assertEquals("logoutUriLinks.length()", expectedLength, logoutUriLinks.length());
        } else {
            assertEquals("logoutUriLinks", "", logoutUriLinks);
        }

        Cookie sessionCookie = response.getCookie(Shared.getSessionCookieName(TENANT_NAME));
        assertEquals("expectingSessionCookie", expectingSessionCookie, sessionCookie != null);
        if (expectingSessionCookie) {
            assertEquals("sessionCookie value is empty", "", sessionCookie.getValue());
        }
    }

    public static void validateLogoutErrorResponse(
            MockHttpServletResponse response,
            String      expectedErrorMessage) throws Exception {
        assertEquals("expectedErrorMessage", expectedErrorMessage, response.getErrorMessage());
        assertTrue("response.getStatus", response.getStatus() == 400 || response.getStatus() == 401);
        assertNull("sessionCookie", response.getCookie(Shared.getSessionCookieName(TENANT_NAME)));
    }

    private static void validateToken(
            String      tokenClass,
            String      tokenString,
            Flow        flow,
            Scope       scope,
            boolean     wSltnAssertion,
            boolean     wClientAssertion,
            String      expectedNonce,
            String      expectedSessionId,
            Set<String> expectedIdTokenGroups,
            Set<String> expectedAccessTokenGroups,
            String      expectedAdminServerRole) throws Exception {
        assertTrue("tokenString not null or empty", tokenString != null && !tokenString.isEmpty());
        SignedJWT token = SignedJWT.parse(tokenString);
        assertNotNull("token", token);

        // verify signature
        JWSVerifier verifier = new RSASSAVerifier(TENANT_PUBLIC_KEY);
        assertTrue(token.verify(verifier));

        Date now = new Date();
        ReadOnlyJWTClaimsSet claimsSet = token.getJWTClaimsSet();

        assertEquals("token_class", tokenClass, claimsSet.getStringClaim("token_class"));
        assertEquals("scope", scope.toString(), claimsSet.getStringClaim("scope"));
        assertEquals("client_id", (wClientAssertion || flow.isImplicit()) ? CLIENT_ID : null, claimsSet.getStringClaim("client_id"));
        assertEquals("tenant", TENANT_NAME, claimsSet.getStringClaim("tenant"));
        assertEquals("issuer", ISSUER, claimsSet.getIssuer());

        String expectedSubject = (flow == Flow.SOLUTION_USER_CREDS || flow == Flow.CLIENT_CREDS) ?
                SOLUTION_USER.getSubject().getValue() :
                PERSON_USER.getSubject().getValue();
        assertEquals("subject", expectedSubject, claimsSet.getSubject());

        String expectedAudience;
        if (wClientAssertion || flow.isImplicit()) {
            expectedAudience = CLIENT_ID;
        } else if (wSltnAssertion) {
            expectedAudience = SOLUTION_USER.getSubject().getValue();
        } else {
            expectedAudience = PERSON_USER.getSubject().getValue();
        }
        assertTrue("audience", claimsSet.getAudience().contains(expectedAudience));

        assertTrue("issued at", claimsSet.getIssueTime().before(now));
        assertTrue("expiration", claimsSet.getExpirationTime().after(now));
        assertNotNull("jwt_id", claimsSet.getJWTID());

        if (flow.isImplicit() || flow == Flow.AUTHZ_CODE) {
            assertNotNull("nonce", claimsSet.getStringClaim("nonce"));
            assertEquals("nonce", expectedNonce, claimsSet.getStringClaim("nonce"));
        } else {
            assertNull("nonce", claimsSet.getStringClaim("nonce"));
        }

        if (flow.isImplicit() || flow == Flow.AUTHZ_CODE) {
            assertNotNull("sid", claimsSet.getStringClaim("sid"));
        }
        if (flow.isImplicit()) {
            assertEquals("sid", expectedSessionId, claimsSet.getStringClaim("sid"));
        }

        assertEquals("token_type", (wSltnAssertion || wClientAssertion) ? "hotk-pk" : "Bearer", claimsSet.getStringClaim("token_type"));

        if (wSltnAssertion || wClientAssertion) {
            JSONObject hotk = (JSONObject) claimsSet.getClaim("hotk");
            assertNotNull("hotk", hotk);
            JWKSet jwkSet = JWKSet.parse(hotk);
            assertNotNull("jwkSet", jwkSet);
            RSAPublicKey publicKey = Shared.extractRsa256PublicKey(jwkSet);
            assertEquals("access_token hotk claim contains CLIENT_PUBLIC_KEY", CLIENT_PUBLIC_KEY, publicKey);

            if (flow != Flow.SOLUTION_USER_CREDS && flow != Flow.CLIENT_CREDS) {
                assertEquals("act_as", SOLUTION_USER.getSubject().getValue(), claimsSet.getStringClaim("act_as"));
            }
        }

        if (tokenClass.equals("id_token")) {
            boolean idGroupsScope = scope.contains("id_groups") || scope.contains("id_groups_filtered");
            boolean idGroupsExist = claimsSet.getClaim("groups") != null;
            assertEquals("idGroupsScope==idGroupsExist", idGroupsScope, idGroupsExist);
            if (idGroupsScope) {
                Set<String> idTokenGroups = new HashSet<String>(Arrays.asList(claimsSet.getStringArrayClaim("groups")));
                assertEquals("idTokenGroups", expectedIdTokenGroups, idTokenGroups);
            }
        } else if (tokenClass.equals("access_token")) {
            boolean atGroupsScope = scope.contains("at_groups") || scope.contains("at_groups_filtered");
            boolean atGroupsExist = claimsSet.getClaim("groups") != null;
            assertEquals("atGroupsScope==atGroupsExist", atGroupsScope, atGroupsExist);
            if (atGroupsExist) {
                Set<String> accessTokenGroups = new HashSet<String>(Arrays.asList(claimsSet.getStringArrayClaim("groups")));
                assertEquals("accessTokenGroups", expectedAccessTokenGroups, accessTokenGroups);
            }

            boolean adminServerScope = scope.contains("rs_admin_server");
            boolean adminServerAudience = claimsSet.getAudience().contains("rs_admin_server");
            boolean adminServerRoleExists = claimsSet.getStringClaim("admin_server_role") != null;
            assertEquals("adminServerScope==adminServerAudience", adminServerScope, adminServerAudience);
            assertEquals("adminServerScope==adminServerRoleExists", adminServerScope, adminServerRoleExists);
            if (adminServerScope) {
                assertEquals("admin_server_role", expectedAdminServerRole, claimsSet.getStringClaim("admin_server_role"));
            }

            boolean rsxScope = scope.contains(SCOPE_VALUE_RSX);
            boolean rsxAudience = claimsSet.getAudience().contains(SCOPE_VALUE_RSX);
            assertEquals("rsxScope==rsxAudience", rsxScope, rsxAudience);
        } else if (tokenClass.equals("refresh_token")) {
            // no-op
        } else {
            throw new IllegalArgumentException("unexpected tokenClass: " + tokenClass);
        }
    }

    private static String extractAuthnResponseTarget(
            Flow flow,
            MockHttpServletResponse response,
            boolean redirectResponseMode,
            boolean ajaxRequest) throws Exception {
        String result;

        if (redirectResponseMode) {
            String redirectUrl = ajaxRequest ? response.getContentAsString() : response.getRedirectedUrl();
            char separator = (flow == Flow.AUTHZ_CODE) ? '?' : '#';
            result = redirectUrl.substring(0, redirectUrl.indexOf(separator));
        } else {
            // response_mode=form_post
            String prefix = "<form method=\"post\" id=\"SamlPostForm\" action=\"";
            result = TestUtil.extractString(response, prefix, "\"");
        }

        return result;
    }

    private static String extractAuthnResponseParameter(
            Flow flow,
            MockHttpServletResponse response,
            String parameterName,
            boolean redirectResponseMode,
            boolean ajaxRequest) throws Exception {
        String result;

        if (redirectResponseMode) {
            String redirectUrl = ajaxRequest ? response.getContentAsString() : response.getRedirectedUrl();
            char separator = (flow == Flow.AUTHZ_CODE) ? '?' : '#';
            String queryString = redirectUrl.substring(redirectUrl.indexOf(separator) + 1);
            Map<String, String> params = URLUtils.parseParameters(queryString);
            result = params.get(parameterName);
        } else {
            String prefix = String.format("<input type=\"hidden\" name=\"%s\" value=\"", parameterName);
            result = TestUtil.extractString(response, prefix, "\"");
        }

        return result;
    }

    private static Map<String, String> tokenRequestAuthzGrantAndScope(
            Flow flow,
            ReadOnlyJWTClaimsSet refreshTokenClaims) throws Exception {
        assert flow.isTokenEndpointFlow();

        Map<String, String> params = new HashMap<String, String>();
        switch (flow) {
            case AUTHZ_CODE:
                params.put("grant_type", "authorization_code");
                params.put("code", AUTHZ_CODE);
                params.put("redirect_uri", REDIRECT_URI.toString());
                break;
            case PASSWORD:
                params.put("grant_type", "password");
                params.put("username", USERNAME);
                params.put("password", PASSWORD);
                params.put("scope", "openid offline_access");
                break;
            case CLIENT_CREDS:
                params.put("grant_type", "client_credentials");
                params.put("scope", "openid");
                break;
            case SOLUTION_USER_CREDS:
                params.put("grant_type", "urn:vmware:grant_type:solution_user_credentials");
                params.put("scope", "openid");
                break;
            case GSS_TICKET:
                params.put("grant_type", "urn:vmware:grant_type:gss_ticket");
                params.put("context_id", GSS_CONTEXT_ID);
                params.put("gss_ticket", "===");
                params.put("scope", "openid offline_access");
                break;
            case REFRESH_TOKEN:
                params.put("grant_type", "refresh_token");
                params.put("refresh_token", Shared.sign(refreshTokenClaims, TENANT_PRIVATE_KEY).serialize());
                break;
            default:
                throw new IllegalArgumentException("unexpected flow: " + flow);
        }
        return params;
    }

    public static class AuthnResponse {
        private final SignedJWT idToken;
        private final SignedJWT accessToken;
        private final String authzCode;

        private AuthnResponse(String idToken, String accessToken, String authzCode) throws Exception {
            this.idToken = (idToken == null) ? null : SignedJWT.parse(idToken);
            this.accessToken = (accessToken == null) ? null : SignedJWT.parse(accessToken);
            this.authzCode = authzCode;
        }

        public SignedJWT getIdToken() {
            return this.idToken;
        }

        public SignedJWT getAccessToken() {
            return this.accessToken;
        }

        public String getAuthzCode() {
            return this.authzCode;
        }
    }

    public static class TokenResponse {
        private final SignedJWT idToken;
        private final SignedJWT accessToken;
        private final SignedJWT refreshToken;

        private TokenResponse(String idToken, String accessToken, String refreshToken) throws Exception {
            this.idToken = SignedJWT.parse(idToken);
            this.accessToken = SignedJWT.parse(accessToken);
            this.refreshToken = (refreshToken == null) ? null : SignedJWT.parse(refreshToken);
        }

        public SignedJWT getIdToken() {
            return this.idToken;
        }

        public SignedJWT getAccessToken() {
            return this.accessToken;
        }

        public SignedJWT getRefreshToken() {
            return this.refreshToken;
        }
    }
}