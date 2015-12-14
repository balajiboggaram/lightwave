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

import java.net.URI;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import javax.servlet.http.Cookie;

import org.apache.commons.lang3.tuple.Pair;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.vmware.identity.diagnostics.DiagnosticsLoggerFactory;
import com.vmware.identity.diagnostics.IDiagnosticsLogger;
import com.vmware.identity.openidconnect.common.HttpRequest;
import com.vmware.identity.openidconnect.common.LogoutRequest;
import com.vmware.identity.openidconnect.common.LogoutSuccessResponse;
import com.vmware.identity.openidconnect.common.SessionID;
import com.vmware.identity.openidconnect.common.TokenClass;

/**
 * @author Yehia Zayour
 */
public class LogoutRequestProcessor {
    private static final long REQUEST_LIFETIME_MS = 2 * 60 * 1000L; // 2 minutes

    private static final IDiagnosticsLogger logger = DiagnosticsLoggerFactory.getLogger(LogoutRequestProcessor.class);

    private final TenantInfoRetriever tenantInfoRetriever;
    private final ClientInfoRetriever clientInfoRetriever;
    private final SolutionUserAuthenticator solutionUserAuthenticator;

    private final SessionManager sessionManager;
    private final HttpRequest httpRequest;
    private final String tenant;

    private TenantInfo tenantInfo;
    private LogoutRequest logoutRequest;

    public LogoutRequestProcessor(
            IdmClient idmClient,
            SessionManager sessionManager,
            HttpRequest httpRequest,
            String tenant) {
        this.tenantInfoRetriever = new TenantInfoRetriever(idmClient);
        this.clientInfoRetriever = new ClientInfoRetriever(idmClient);
        this.solutionUserAuthenticator = new SolutionUserAuthenticator(idmClient);

        this.sessionManager = sessionManager;
        this.httpRequest = httpRequest;
        this.tenant = tenant;

        // set by initialize()
        this.tenantInfo = null;
        this.logoutRequest = null;
    }

    public HttpResponse process() {
        HttpResponse httpResponse;

        try {
            initialize();
            Pair<LogoutSuccessResponse, Cookie> result = processInternal();
            httpResponse = HttpResponse.success(result.getLeft(), result.getRight());
        } catch (ServerException e) {
            Shared.logFailedRequest(logger, e);
            httpResponse = HttpResponse.error(e);
        }

        return httpResponse;
    }

    private void initialize() throws ServerException {
        try {
            this.logoutRequest = LogoutRequest.parse(this.httpRequest);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription(e.getMessage()), e);
        }

        String tenantName = this.tenant;
        if (tenantName == null) {
            tenantName = this.tenantInfoRetriever.getDefaultTenantName();
        }
        this.tenantInfo = this.tenantInfoRetriever.retrieveTenantInfo(tenantName);
    }

    private Pair<LogoutSuccessResponse, Cookie> processInternal() throws ServerException {
        String sessionIdString = this.httpRequest.getCookieValue(Shared.getSessionCookieName(this.tenantInfo.getName()));
        SessionID sessionId = null;
        SessionManager.Entry entry = null;
        if (sessionIdString != null) {
            sessionId = new SessionID(sessionIdString);
            entry = this.sessionManager.get(sessionId);
        }

        SignedJWT idTokenJwt = this.logoutRequest.getIDTokenHint().getSignedJWT();

        boolean validSignature;
        try {
            validSignature = idTokenJwt.verify(new RSASSAVerifier(this.tenantInfo.getPublicKey()));
        } catch (JOSEException e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("error while verifying id_token signature"), e);
        }
        if (!validSignature) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("id_token has an invalid signature"));
        }

        ReadOnlyJWTClaimsSet idTokenClaimsSet;
        try {
            idTokenClaimsSet = idTokenJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("failed to parse claims out of id_token"), e);
        }

        ErrorObject error = validateIdTokenClaims(idTokenClaimsSet, entry);
        if (error != null) {
            throw new ServerException(error);
        }

        ClientID clientId = new ClientID(idTokenClaimsSet.getAudience().get(0));
        ClientInfo clientInfo = this.clientInfoRetriever.retrieveClientInfo(this.tenantInfo.getName(), clientId);
        if (clientInfo.getCertSubjectDn() != null) {
            if (this.logoutRequest.getClientAssertion() != null) {
                this.solutionUserAuthenticator.authenticateByClientAssertion(
                        this.logoutRequest.getClientAssertion(),
                        REQUEST_LIFETIME_MS,
                        this.httpRequest.getRequestUrl(),
                        this.tenantInfo,
                        clientInfo);
            } else {
                throw new ServerException(OAuth2Error.INVALID_CLIENT.setDescription("client_assertion parameter is required since client has registered a cert"));
            }
        }

        if (this.logoutRequest.getPostLogoutRedirectionURI() != null) {
            if (!clientInfo.getPostLogoutRedirectUris().contains(this.logoutRequest.getPostLogoutRedirectionURI())) {
                throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("unregistered post_logout_redirect_uri"));
            }
        }

        // SLO using OpenID Connect HTTP-Based Logout 1.0 - draft 03
        // construct iframe links containing logout_uri requests, the browser will send these to other participating clients
        // do not include the client that initiated this logout request as that client has already logged out before sending us this request
        Set<URI> logoutUris = new HashSet<URI>();
        if (entry != null) {
            for (ClientInfo client : entry.getClients()) {
                if (client.getLogoutUri() != null && !client.getID().equals(clientId)) {
                    logoutUris.add(client.getLogoutUri());
                }
            }
            this.sessionManager.remove(sessionId);
        }

        return Pair.of(
                new LogoutSuccessResponse(
                    this.logoutRequest.getPostLogoutRedirectionURI(),
                    this.logoutRequest.getState(),
                    sessionId,
                    logoutUris),
                (sessionId == null) ? null : wipeOutSessionCookie());
    }

    private ErrorObject validateIdTokenClaims(ReadOnlyJWTClaimsSet claimsSet, SessionManager.Entry entry) {
        ErrorObject error = CommonValidator.validateBaseJwtClaims(claimsSet, TokenClass.ID_TOKEN);

        if (error == null && !Objects.equals(this.tenantInfo.getIssuer().getValue(), claimsSet.getIssuer())) {
            error = OAuth2Error.INVALID_REQUEST.setDescription("id_token has incorrect issuer");
        }

        if (error == null && entry != null && !Objects.equals(entry.getPersonUser().getSubject().getValue(), claimsSet.getSubject())) {
            error = OAuth2Error.INVALID_REQUEST.setDescription("id_token subject does not match the session user");
        }

        if (error == null && claimsSet.getAudience().size() != 1) {
            error = OAuth2Error.INVALID_REQUEST.setDescription("id_token must have a single audience value containing the client_id");
        }

        return error;
    }

    private Cookie wipeOutSessionCookie() {
        Cookie sessionCookie = new Cookie(Shared.getSessionCookieName(this.tenantInfo.getName()), "");
        sessionCookie.setPath("/openidconnect");
        sessionCookie.setSecure(true);
        sessionCookie.setHttpOnly(true);
        sessionCookie.setMaxAge(0);
        return sessionCookie;
    }
}