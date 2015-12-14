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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.Validate;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.vmware.identity.openidconnect.common.HolderOfKeyAccessToken;
import com.vmware.identity.openidconnect.common.IDToken;
import com.vmware.identity.openidconnect.common.SessionID;
import com.vmware.identity.openidconnect.common.TokenClass;
import com.vmware.identity.openidconnect.common.TokenType;

/**
 * @author Yehia Zayour
 */
public class TokenIssuer {
    private final PersonUser personUser;
    private final SolutionUser solutionUser;
    private final UserInfo userInfo;
    private final TenantInfo tenantInfo;
    private final Scope scope;
    private final Nonce nonce;
    private final ClientID clientId;
    private final SessionID sessionId;

    public TokenIssuer(
            PersonUser personUser,
            SolutionUser solutionUser,
            UserInfo userInfo,
            TenantInfo tenantInfo,
            Scope scope,
            Nonce nonce,
            ClientID clientId,
            SessionID sessionId) {
        Validate.isTrue(personUser != null || solutionUser != null, "personUser and solutionUser should not both be null");
        Validate.notNull(userInfo, "userInfo");
        Validate.notNull(tenantInfo, "tenantInfo");
        Validate.notNull(scope, "scope");
        // nullable nonce
        // nullable clientId
        // nullable sessionId

        this.personUser = personUser;
        this.solutionUser = solutionUser;
        this.userInfo = userInfo;
        this.tenantInfo = tenantInfo;
        this.scope = scope;
        this.nonce = nonce;
        this.clientId = clientId;
        this.sessionId = sessionId;
    }

    public IDToken issueIdToken() throws ServerException {
        long lifeTimeMs = (this.solutionUser != null) ?
                this.tenantInfo.getIdTokenHokLifetimeMs() :
                this.tenantInfo.getIdTokenBearerLifetimeMs();

        JWTClaimsSet claimsSet = commonClaims(TokenClass.ID_TOKEN, lifeTimeMs);

        if (this.personUser != null) {
            claimsSet.setClaim("given_name", this.userInfo.getGivenName());
            claimsSet.setClaim("family_name", this.userInfo.getFamilyName());
        }

        if (this.scope.contains(ScopeValue.ID_TOKEN_GROUPS.getName())) {
            claimsSet.setClaim("groups", this.userInfo.getGroupMembership());
        } else if (this.scope.contains(ScopeValue.ID_TOKEN_GROUPS_FILTERED.getName())) {
            Collection<String> groups =
                    this.userInfo.getGroupMembershipFiltered() != null ?
                    this.userInfo.getGroupMembershipFiltered() :
                    this.userInfo.getGroupMembership();
            claimsSet.setClaim("groups", groups);
        }

        SignedJWT signedJwt = Shared.sign(claimsSet, this.tenantInfo.getPrivateKey());
        return new IDToken(signedJwt);
    }

    public AccessToken issueAccessToken() throws ServerException {
        long lifeTimeMs = (this.solutionUser != null) ?
                this.tenantInfo.getAccessTokenHokLifetimeMs() :
                this.tenantInfo.getAccessTokenBearerLifetimeMs();

        JWTClaimsSet claimsSet = commonClaims(TokenClass.ACCESS_TOKEN, lifeTimeMs);

        if (this.scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS.getName())) {
            claimsSet.setClaim("groups", this.userInfo.getGroupMembership());
        } else if (this.scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS_FILTERED.getName())) {
            Collection<String> groups =
                    this.userInfo.getGroupMembershipFiltered() != null ?
                    this.userInfo.getGroupMembershipFiltered() :
                    this.userInfo.getGroupMembership();
            claimsSet.setClaim("groups", groups);
        }

        if (this.scope.contains(ScopeValue.RESOURCE_SERVER_ADMIN_SERVER.getName())) {
            claimsSet.setClaim("admin_server_role", this.userInfo.getAdminServerRole());
        }

        SignedJWT signedJWT = Shared.sign(claimsSet, this.tenantInfo.getPrivateKey());
        return (this.solutionUser != null) ?
                new HolderOfKeyAccessToken(signedJWT.serialize(), lifeTimeMs / 1000L) :
                new BearerAccessToken(signedJWT.serialize(), lifeTimeMs / 1000L, (Scope) null);
    }

    public RefreshToken issueRefreshToken() throws ServerException {
        long lifeTimeMs = (this.solutionUser != null) ?
                this.tenantInfo.getRefreshTokenHokLifetimeMs() :
                this.tenantInfo.getRefreshTokenBearerLifetimeMs();
        JWTClaimsSet claimsSet = commonClaims(TokenClass.REFRESH_TOKEN, lifeTimeMs);
        SignedJWT signedJWT = Shared.sign(claimsSet, this.tenantInfo.getPrivateKey());
        return new RefreshToken(signedJWT.serialize());
    }

    private JWTClaimsSet commonClaims(TokenClass tokenClass, long lifeTimeMs) {
        Date now = new Date();

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setClaim("token_class", tokenClass.getName());
        claimsSet.setClaim("token_type", (this.solutionUser != null) ? TokenType.HOK.getName() : TokenType.BEARER.getName());
        claimsSet.setJWTID((new JWTID()).toString());

        // bind the public key to the hok access token by inserting it as a claim
        if (this.solutionUser != null) {
            RSAKey rsaKey = new RSAKey(this.solutionUser.getPublicKey(), KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, null, null, null, null);
            claimsSet.setClaim("hotk", (new JWKSet(rsaKey)).toJSONObject());
        }

        // this claim represents the identity of the solution user Acting As the person user
        if (this.personUser != null && this.solutionUser != null) {
            claimsSet.setClaim("act_as", this.solutionUser.getSubject().getValue());
        }

        claimsSet.setClaim("tenant", this.tenantInfo.getName());
        claimsSet.setIssuer(this.tenantInfo.getIssuer().getValue());

        Subject subject = (this.personUser != null) ? this.personUser.getSubject() : this.solutionUser.getSubject();
        claimsSet.setSubject(subject.getValue());

        List<String> audience = new ArrayList<String>();
        if (this.clientId != null) {
            audience.add(this.clientId.getValue());
        } else if (this.solutionUser != null) {
            audience.add(this.solutionUser.getSubject().getValue());
        } else {
            audience.add(this.personUser.getSubject().getValue());
        }
        if (tokenClass == TokenClass.ACCESS_TOKEN) {
            for (String scopeValue : this.scope.toStringList()) {
                if (scopeValue.startsWith(ScopeValue.RESOURCE_SERVER_PREFIX)) {
                    audience.add(scopeValue);
                }
            }
        }
        claimsSet.setAudience(audience);

        claimsSet.setIssueTime(now);
        claimsSet.setExpirationTime(new Date(now.getTime() + lifeTimeMs));
        claimsSet.setClaim("scope", this.scope.toString());

        if (this.clientId != null) {
            claimsSet.setClaim("client_id", this.clientId.getValue());
        }
        if (this.nonce != null) {
            claimsSet.setClaim("nonce", this.nonce.getValue());
        }
        if (this.sessionId != null) {
            claimsSet.setClaim("sid", this.sessionId.getValue());
        }

        return claimsSet;
    }
}