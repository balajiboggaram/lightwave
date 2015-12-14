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

import java.text.ParseException;

import org.apache.commons.lang3.Validate;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.vmware.identity.openidconnect.common.SolutionUserCredentialsGrant;
import com.vmware.identity.openidconnect.common.TokenClass;

/**
 * @author Yehia Zayour
 */
public class CommonValidator {
    public static ErrorObject validateBaseJwtClaims(ReadOnlyJWTClaimsSet claimsSet, TokenClass expectedTokenClass) {
        Validate.notNull(claimsSet, "claimsSet");
        Validate.notNull(expectedTokenClass, "expectedTokenClass");

        String error = null;

        String tokenClassString = null;
        try {
            tokenClassString = claimsSet.getStringClaim("token_class");
        } catch (ParseException e) {
            error = "has non-string token_class claim";
        }

        if (error == null && tokenClassString == null) {
            error = "is missing token_class claim";
        }

        if (error == null && !tokenClassString.equals(expectedTokenClass.getName())) {
            error = "has incorrect token_class claim";
        }

        if (error == null && claimsSet.getIssuer() == null) {
            error = "is missing iss (issuer) claim";
        }

        if (error == null && claimsSet.getSubject() == null) {
            error = "is missing sub (subject) claim";
        }

        if (error == null && claimsSet.getAudience() == null) {
            error = "is missing aud (audience) claim";
        }

        if (error == null && claimsSet.getIssueTime() == null) {
            error = "is missing iat (issued at) claim";
        }

        if (error == null && claimsSet.getExpirationTime() == null) {
            error = "is missing exp (expiration) claim";
        }

        if (error == null && claimsSet.getJWTID() == null) {
            error = "is missing jti (jwt id) claim";
        }

        return (error == null) ? null : OAuth2Error.INVALID_REQUEST.setDescription(expectedTokenClass.getName() + " " + error);
    }

    public static ErrorObject validateScope(Scope scope, GrantType grantType) {
        Validate.notNull(scope, "scope");
        Validate.notNull(grantType, "grantType");

        ErrorObject error = null;

        if (!scope.contains(OIDCScopeValue.OPENID)) {
            error = OAuth2Error.INVALID_REQUEST.setDescription("missing openid scope value");
        }

        boolean resourceServerRequested = false;
        if (error == null) {
            for (String scopeValue : scope.toStringList()) {
                boolean validResourceServerName =
                        scopeValue.startsWith(ScopeValue.RESOURCE_SERVER_PREFIX) &&
                        scopeValue.length() > (ScopeValue.RESOURCE_SERVER_PREFIX.length());
                if (validResourceServerName) {
                    resourceServerRequested = true;
                }
                boolean valid =
                        validResourceServerName ||
                        scopeValue.equals(OIDCScopeValue.OPENID.toString()) ||
                        scopeValue.equals(OIDCScopeValue.OFFLINE_ACCESS.toString()) ||
                        ScopeValue.isDefined(scopeValue);
                if (!valid) {
                    error = OAuth2Error.INVALID_SCOPE.setDescription("unrecognized scope value: " + scopeValue);
                    break;
                }
            }
        }

        if (error == null &&
                scope.contains(ScopeValue.ID_TOKEN_GROUPS.getName()) &&
                scope.contains(ScopeValue.ID_TOKEN_GROUPS_FILTERED.getName())) {
            error = OAuth2Error.INVALID_SCOPE.setDescription("id_groups together with id_groups_filtered is not allowed");
        }

        if (error == null &&
                scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS.getName()) &&
                scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS_FILTERED.getName())) {
            error = OAuth2Error.INVALID_SCOPE.setDescription("at_groups together with at_groups_filtered is not allowed");
        }

        if (error == null &&
                scope.contains(ScopeValue.ID_TOKEN_GROUPS_FILTERED.getName()) &&
                !resourceServerRequested) {
            error = OAuth2Error.INVALID_SCOPE.setDescription("id_token filtered groups requested but no resource server requested");
        }

        if (error == null) {
            boolean accessTokenGroupsRequested =
                    scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS.getName()) ||
                    scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS_FILTERED.getName());
            if (accessTokenGroupsRequested && !resourceServerRequested) {
                error = OAuth2Error.INVALID_SCOPE.setDescription("access_token groups requested but no resource server requested");
            }
        }

        if (error == null) {
            boolean refreshTokenDisallowed =
                    grantType.equals(GrantType.IMPLICIT) ||
                    grantType.equals(ClientCredentialsGrant.GRANT_TYPE) ||
                    grantType.equals(SolutionUserCredentialsGrant.GRANT_TYPE);
            if (refreshTokenDisallowed && scope.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
                error = OAuth2Error.INVALID_SCOPE.setDescription("refresh token (offline_access) is not allowed for this grant_type");
            }
        }

        return error;
    }
}