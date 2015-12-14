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
import java.util.Date;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.vmware.identity.diagnostics.DiagnosticsLoggerFactory;
import com.vmware.identity.diagnostics.IDiagnosticsLogger;
import com.vmware.identity.idm.GSSResult;
import com.vmware.identity.openidconnect.common.AuthenticationRequest;
import com.vmware.identity.openidconnect.common.GssTicketGrant;
import com.vmware.identity.openidconnect.common.HttpRequest;
import com.vmware.identity.openidconnect.common.IDToken;
import com.vmware.identity.openidconnect.common.SessionID;
import com.vmware.identity.openidconnect.common.SolutionUserCredentialsGrant;
import com.vmware.identity.openidconnect.common.TokenClass;
import com.vmware.identity.openidconnect.common.TokenErrorResponse;
import com.vmware.identity.openidconnect.common.TokenRequest;
import com.vmware.identity.openidconnect.common.TokenSuccessResponse;

/**
 * @author Yehia Zayour
 */
public class TokenRequestProcessor {
    private static final long REQUEST_LIFETIME_MS   = 1 * 60 * 1000L; // 1 minute

    private static final IDiagnosticsLogger logger = DiagnosticsLoggerFactory.getLogger(TokenRequestProcessor.class);

    private final TenantInfoRetriever tenantInfoRetriever;
    private final ClientInfoRetriever clientInfoRetriever;
    private final ServerInfoRetriever serverInfoRetriever;
    private final UserInfoRetriever userInfoRetriever;
    private final PersonUserAuthenticator personUserAuthenticator;
    private final SolutionUserAuthenticator solutionUserAuthenticator;

    private final AuthorizationCodeManager authzCodeManager;
    private final HttpRequest httpRequest;
    private final String tenant;

    private TenantInfo tenantInfo;
    private TokenRequest tokenRequest;

    public TokenRequestProcessor(
            IdmClient idmClient,
            AuthorizationCodeManager authzCodeManager,
            HttpRequest httpRequest,
            String tenant) {
        this.tenantInfoRetriever = new TenantInfoRetriever(idmClient);
        this.clientInfoRetriever = new ClientInfoRetriever(idmClient);
        this.serverInfoRetriever = new ServerInfoRetriever(idmClient);
        this.userInfoRetriever = new UserInfoRetriever(idmClient);
        this.personUserAuthenticator = new PersonUserAuthenticator(idmClient);
        this.solutionUserAuthenticator = new SolutionUserAuthenticator(idmClient);

        this.authzCodeManager = authzCodeManager;
        this.httpRequest = httpRequest;
        this.tenant = tenant;

        // set by initialize()
        this.tenantInfo = null;
        this.tokenRequest = null;
    }

    public HttpResponse process() {
        TokenResponse tokenResponse;

        try {
            initialize();
            tokenResponse = processInternal(); // TokenSuccessResponse
        } catch (ServerException e) {
            Shared.logFailedRequest(logger, e);
            tokenResponse = new TokenErrorResponse(e.getErrorObject());
        }

        return HttpResponse.success(tokenResponse);
    }

    private void initialize() throws ServerException {
        try {
            this.tokenRequest = TokenRequest.parse(this.httpRequest);
        } catch (ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription(e.getMessage()), e);
        }

        ErrorObject error = validate();
        if (error != null) {
            throw new ServerException(error);
        }

        String tenantName = this.tenant;
        if (tenantName == null) {
            tenantName = this.tenantInfoRetriever.getDefaultTenantName();
        }
        this.tenantInfo = this.tenantInfoRetriever.retrieveTenantInfo(tenantName);
    }

    private TokenSuccessResponse processInternal() throws ServerException {
        GrantType grantType = this.tokenRequest.getAuthorizationGrant().getType();

        SolutionUser solutionUser = null;
        try {
            if (this.tokenRequest.getClientAssertion() != null) {
                ClientInfo clientInfo = this.clientInfoRetriever.retrieveClientInfo(this.tenantInfo.getName(), this.tokenRequest.getClientID());
                solutionUser = this.solutionUserAuthenticator.authenticateByClientAssertion(
                        this.tokenRequest.getClientAssertion(),
                        REQUEST_LIFETIME_MS,
                        this.httpRequest.getRequestUrl(),
                        this.tenantInfo,
                        clientInfo);
            } else if (this.tokenRequest.getSolutionAssertion() != null) {
                solutionUser = this.solutionUserAuthenticator.authenticateBySolutionAssertion(
                        this.tokenRequest.getSolutionAssertion(),
                        REQUEST_LIFETIME_MS,
                        this.httpRequest.getRequestUrl(),
                        this.tenantInfo);
            }
        } catch (ServerException e) {
            if ((grantType.equals(SolutionUserCredentialsGrant.GRANT_TYPE) || grantType.equals(ClientCredentialsGrant.GRANT_TYPE)) &&
                !Objects.equals(e.getErrorObject().getCode(), OAuth2Error.SERVER_ERROR.getCode())) {
                throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription(e.getErrorObject().getDescription()));
            } else {
                throw e;
            }
        }

        TokenSuccessResponse tokenSuccessResponse;
        if (grantType.equals(AuthorizationCodeGrant.GRANT_TYPE)) {
            tokenSuccessResponse = processAuthzCodeGrant(solutionUser);
        } else if (grantType.equals(ResourceOwnerPasswordCredentialsGrant.GRANT_TYPE)) {
            tokenSuccessResponse = processPasswordCredentialsGrant(solutionUser);
        } else if (grantType.equals(ClientCredentialsGrant.GRANT_TYPE)) {
            tokenSuccessResponse = processClientCredentialsGrant(solutionUser);
        } else if (grantType.equals(SolutionUserCredentialsGrant.GRANT_TYPE)) {
            tokenSuccessResponse = processSolutionUserCredentialsGrant(solutionUser);
        } else if (grantType.equals(GssTicketGrant.GRANT_TYPE)) {
            tokenSuccessResponse = processGssTicketGrant(solutionUser);
        } else if (grantType.equals(RefreshTokenGrant.GRANT_TYPE)) {
            tokenSuccessResponse = processRefreshTokenGrant(solutionUser);
        } else {
            throw new IllegalStateException("unexpected grant_type: " + grantType);
        }
        return tokenSuccessResponse;
    }

    private TokenSuccessResponse processAuthzCodeGrant(SolutionUser solutionUser) throws ServerException {
        AuthorizationCodeGrant authzCodeGrant = (AuthorizationCodeGrant) this.tokenRequest.getAuthorizationGrant();
        AuthorizationCode authzCode = authzCodeGrant.getAuthorizationCode();
        URI redirectUri = authzCodeGrant.getRedirectionURI();

        AuthorizationCodeManager.Entry entry = this.authzCodeManager.remove(authzCode);
        ErrorObject error = validateAuthzCode(entry, redirectUri);
        if (error != null) {
            throw new ServerException(error);
        }

        return process(
                entry.getPersonUser(),
                solutionUser,
                entry.getAuthenticationRequest().getClientID(),
                entry.getAuthenticationRequest().getScope(),
                entry.getAuthenticationRequest().getNonce(),
                entry.getSessionId(),
                true /* refreshTokenAllowed */);
    }

    private TokenSuccessResponse processClientCredentialsGrant(SolutionUser solutionUser) throws ServerException {
        assert this.tokenRequest.getAuthorizationGrant() instanceof ClientCredentialsGrant;
        return process(
                (PersonUser) null,
                solutionUser,
                this.tokenRequest.getClientID(),
                this.tokenRequest.getScope(),
                (Nonce) null,
                (SessionID) null,
                false /* refreshTokenAllowed */);
    }

    private TokenSuccessResponse processSolutionUserCredentialsGrant(SolutionUser solutionUser) throws ServerException {
        assert this.tokenRequest.getAuthorizationGrant() instanceof SolutionUserCredentialsGrant;
        return process(
                (PersonUser) null,
                solutionUser,
                this.tokenRequest.getClientID(),
                this.tokenRequest.getScope(),
                (Nonce) null,
                (SessionID) null,
                false /* refreshTokenAllowed */);
    }

    private TokenSuccessResponse processPasswordCredentialsGrant(SolutionUser solutionUser) throws ServerException {
        ResourceOwnerPasswordCredentialsGrant passwordGrant = (ResourceOwnerPasswordCredentialsGrant) this.tokenRequest.getAuthorizationGrant();
        String username = passwordGrant.getUsername();
        Secret password = passwordGrant.getPassword();

        PersonUser personUser;
        try {
            personUser = this.personUserAuthenticator.authenticate(this.tenantInfo.getName(), username, password.getValue());
        } catch (InvalidCredentialsException e) {
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription("incorrect username or password"), e);
        }

        return process(
                personUser,
                solutionUser,
                this.tokenRequest.getClientID(),
                this.tokenRequest.getScope(),
                (Nonce) null,
                (SessionID) null,
                true /* refreshTokenAllowed */);
    }

    private TokenSuccessResponse processGssTicketGrant(SolutionUser solutionUser) throws ServerException {
        GssTicketGrant gssTicketGrant = (GssTicketGrant) this.tokenRequest.getAuthorizationGrant();
        byte[] gssTicket = gssTicketGrant.getGssTicket();
        String contextId = gssTicketGrant.getContextId();

        GSSResult gssResult;
        try {
            gssResult = this.personUserAuthenticator.authenticate(this.tenantInfo.getName(), contextId, gssTicket);
        } catch (InvalidCredentialsException e) {
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription("invalid gss ticket"), e);
        }

        PersonUser personUser;
        if (gssResult.complete()) {
            personUser = new PersonUser(gssResult.getPrincipalId(), this.tenantInfo.getName());
        } else {
            String base64OfServerLeg = Base64.encode(gssResult.getServerLeg()).toString();
            String message = String.format("gss_continue_needed:%s:%s", contextId, base64OfServerLeg);
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription(message));
        }

        return process(
                personUser,
                solutionUser,
                this.tokenRequest.getClientID(),
                this.tokenRequest.getScope(),
                (Nonce) null,
                (SessionID) null,
                true /* refreshTokenAllowed */);
    }

    private TokenSuccessResponse processRefreshTokenGrant(SolutionUser solutionUser) throws ServerException {
        RefreshTokenGrant refreshTokenGrant = (RefreshTokenGrant) this.tokenRequest.getAuthorizationGrant();
        RefreshToken refreshToken = refreshTokenGrant.getRefreshToken();

        SignedJWT signedJwt;
        try {
            signedJwt = SignedJWT.parse(refreshToken.getValue());
        } catch (java.text.ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription("failed to parse SignedJWT out of refresh_token"), e);
        }

        boolean validSignature;
        try {
            validSignature = signedJwt.verify(new RSASSAVerifier(this.tenantInfo.getPublicKey()));
        } catch (JOSEException e) {
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription("error while verifying refresh_token signature"), e);
        }
        if (!validSignature) {
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription("refresh_token has an invalid signature"));
        }

        ReadOnlyJWTClaimsSet claimsSet;
        try {
            claimsSet = signedJwt.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription("failed to parse claims out of refresh_token"), e);
        }

        ErrorObject error = validateRefreshTokenClaims(claimsSet, solutionUser);
        if (error != null) {
            throw new ServerException(error);
        }

        String scopeString;
        String clientIdString;
        String sessionIdString;
        try {
            scopeString     = claimsSet.getStringClaim("scope");
            clientIdString  = claimsSet.getStringClaim("client_id");
            sessionIdString = claimsSet.getStringClaim("sid");
        } catch (java.text.ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription("refresh_token claims have incorrect type"), e);
        }

        PersonUser personUser;
        try {
            personUser = PersonUser.parse(claimsSet.getSubject(), this.tenantInfo.getName());
        } catch (java.text.ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_GRANT.setDescription("failed to parse subject into a PersonUser"), e);
        }

        return process(
                personUser,
                solutionUser,
                (clientIdString == null) ? null : new ClientID(clientIdString),
                Scope.parse(scopeString),
                (Nonce) null,
                (sessionIdString == null) ? null : new SessionID(sessionIdString),
                false /* refreshTokenAllowed */);
    }

    private TokenSuccessResponse process(
            PersonUser personUser,
            SolutionUser solutionUser,
            ClientID clientId,
            Scope scope,
            Nonce nonce,
            SessionID sessionId,
            boolean refreshTokenAllowed) throws ServerException {
        User user = (personUser != null) ? personUser : solutionUser;
        Set<ResourceServerInfo> resourceServerInfos = this.serverInfoRetriever.retrieveResourceServerInfos(this.tenantInfo.getName(), scope);
        UserInfo userInfo = this.userInfoRetriever.retrieveUserInfo(user, scope, resourceServerInfos);

        if (personUser != null && solutionUser != null) {
            boolean isMemberOfActAsGroup = this.userInfoRetriever.isMemberOfGroup(solutionUser, "ActAsUsers");
            if (!isMemberOfActAsGroup) {
                throw new ServerException(OAuth2Error.ACCESS_DENIED.setDescription("solution user acting as a person user must be a member of ActAsUsers group"));
            }
        }

        TokenIssuer tokenIssuer = new TokenIssuer(
                personUser,
                solutionUser,
                userInfo,
                this.tenantInfo,
                scope,
                nonce,
                clientId,
                sessionId);

        IDToken idToken = tokenIssuer.issueIdToken();
        AccessToken accessToken = tokenIssuer.issueAccessToken();
        RefreshToken refreshToken = null;
        if (refreshTokenAllowed && scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
            refreshToken = tokenIssuer.issueRefreshToken();
        }

        return new TokenSuccessResponse(idToken, accessToken, refreshToken);
    }

    private ErrorObject validate() {
        ErrorObject error = null;

        GrantType grantType = this.tokenRequest.getAuthorizationGrant().getType();
        boolean grantTypeSupported =
                (grantType.equals(AuthorizationCodeGrant.GRANT_TYPE)) ||
                (grantType.equals(ResourceOwnerPasswordCredentialsGrant.GRANT_TYPE)) ||
                (grantType.equals(ClientCredentialsGrant.GRANT_TYPE)) ||
                (grantType.equals(SolutionUserCredentialsGrant.GRANT_TYPE)) ||
                (grantType.equals(GssTicketGrant.GRANT_TYPE)) ||
                (grantType.equals(RefreshTokenGrant.GRANT_TYPE));
        if (!grantTypeSupported) {
            error = OAuth2Error.UNSUPPORTED_GRANT_TYPE;
        }

        if (error == null && this.tokenRequest.getScope() != null) {
            error = CommonValidator.validateScope(this.tokenRequest.getScope(), grantType);
        }

        return error;
    }

    private ErrorObject validateAuthzCode(AuthorizationCodeManager.Entry entry, URI tokenRequestRedirectUri) {
        String error = null;

        if (entry == null) {
            error = "invalid authorization code";
        }

        if (error == null) {
            // in authz code flow, the client_id and redirect_uri in the token request must match those in the original authn request
            AuthenticationRequest originalAuthnRequest = entry.getAuthenticationRequest();
            if (!originalAuthnRequest.getClientID().equals(this.tokenRequest.getClientID())) {
                error = "client_id does not match that of the original authn request";
            } else if (!originalAuthnRequest.getRedirectionURI().equals(tokenRequestRedirectUri)) {
                error = "redirect_uri does not match that of the original authn request";
            }
        }

        if (error == null && !entry.getPersonUser().getTenant().equals(this.tenantInfo.getName())) {
            error = "tenant does not match that of the original authn request";
        }

        return (error == null) ? null : OAuth2Error.INVALID_GRANT.setDescription(error);
    }

    private ErrorObject validateRefreshTokenClaims(ReadOnlyJWTClaimsSet claimsSet, SolutionUser solutionUser) {
        ErrorObject claimsError  = CommonValidator.validateBaseJwtClaims(claimsSet, TokenClass.REFRESH_TOKEN);
        String error = (claimsError == null) ? null : claimsError.getDescription();

        String scope      = null;
        String actAs      = null;
        String clientId   = null;
        String tenant     = null;
        if (error == null) {
            try {
                scope       = claimsSet.getStringClaim("scope");
                actAs       = claimsSet.getStringClaim("act_as");
                clientId    = claimsSet.getStringClaim("client_id");
                tenant      = claimsSet.getStringClaim("tenant");
            } catch (java.text.ParseException e) {
                error = "refresh_token claims have incorrect type";
            }
        }

        if (error == null && StringUtils.isEmpty(scope)) {
            error = "refresh_token is missing scope claim";
        }

        if (error == null) {
            ErrorObject scopeError = CommonValidator.validateScope(Scope.parse(scope), RefreshTokenGrant.GRANT_TYPE);
            if (scopeError != null) {
                error = scopeError.getDescription();
            }
        }

        if (error == null && !this.tenantInfo.getName().equals(tenant)) {
            error = "refresh_token was not issued to this tenant";
        }

        String expectedClientId = (this.tokenRequest.getClientID() == null) ? null : this.tokenRequest.getClientID().getValue();
        if (error == null && !Objects.equals(clientId, expectedClientId)) {
            error = "refresh_token was not issued to this client";
        }

        String expectedActAs = (solutionUser == null) ? null : solutionUser.getSubject().getValue();
        if (error == null && !Objects.equals(actAs, expectedActAs)) {
            error = "refresh_token was not issued to this solution user";
        }

        if (error == null) {
            Date now = new Date();
            Date adjustedExpirationTime = new Date(claimsSet.getExpirationTime().getTime() + this.tenantInfo.getClockToleranceMs());
            if (now.after(adjustedExpirationTime)) {
                error = "refresh_token has expired";
            }
        }

        return (error == null) ? null : OAuth2Error.INVALID_GRANT.setDescription(error);
    }
}