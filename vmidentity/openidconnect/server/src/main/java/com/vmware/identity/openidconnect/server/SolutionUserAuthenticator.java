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

import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.Validate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.vmware.identity.openidconnect.common.TokenClass;

/**
 * @author Yehia Zayour
 */
public class SolutionUserAuthenticator {
    private final IdmClient idmClient;

    public SolutionUserAuthenticator(IdmClient idmClient) {
        Validate.notNull(idmClient, "idmClient");
        this.idmClient = idmClient;
    }

    public SolutionUser authenticateBySolutionAssertion(
            SignedJWT solutionAssertion,
            long solutionAssertionLifetimeMs,
            URL requestUrl,
            TenantInfo tenantInfo) throws ServerException {
        return authenticateByAssertion(solutionAssertion, solutionAssertionLifetimeMs, requestUrl, tenantInfo, (ClientInfo) null);
    }

    public SolutionUser authenticateByClientAssertion(
            SignedJWT clientAssertion,
            long clientAssertionLifetimeMs,
            URL requestUrl,
            TenantInfo tenantInfo,
            ClientInfo clientInfo) throws ServerException {
        Validate.notNull(clientInfo, "clientInfo");
        return authenticateByAssertion(clientAssertion, clientAssertionLifetimeMs, requestUrl, tenantInfo, clientInfo);
    }

    private SolutionUser authenticateByAssertion(
            SignedJWT assertion,
            long assertionLifetimeMs,
            URL requestUrl,
            TenantInfo tenantInfo,
            ClientInfo clientInfo) throws ServerException {
        Validate.notNull(assertion, "assertion");
        Validate.isTrue(assertionLifetimeMs > 0, "assertionLifetimeMs should be positive");
        Validate.notNull(requestUrl, "requestUrl");
        Validate.notNull(tenantInfo, "tenantInfo");

        SolutionUser solutionUser;

        ReadOnlyJWTClaimsSet claimsSet;
        try {
            claimsSet = assertion.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_CLIENT.setDescription("failed to parse claims out of assertion"), e);
        }

        ErrorObject error = validateAssertionClaims(claimsSet, assertionLifetimeMs, requestUrl, tenantInfo, clientInfo);
        if (error != null) {
            throw new ServerException(error);
        }

        String certSubjectDn;
        if (clientInfo != null) {
            certSubjectDn = clientInfo.getCertSubjectDn();
            if (certSubjectDn == null) {
                throw new ServerException(OAuth2Error.INVALID_CLIENT.setDescription("client authn failed because client did not register a cert"));
            }
        } else {
            certSubjectDn = claimsSet.getIssuer();
        }

        solutionUser = retrieveSolutionUser(tenantInfo.getName(), certSubjectDn);

        boolean validSignature;
        try {
            validSignature = assertion.verify(new RSASSAVerifier(solutionUser.getPublicKey()));
        } catch (JOSEException e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("error while verifying assertion signature"), e);
        }
        if (!validSignature) {
            throw new ServerException(OAuth2Error.INVALID_CLIENT.setDescription("assertion has an invalid signature"));
        }

        return solutionUser;
    }

    private SolutionUser retrieveSolutionUser(String tenant, String certSubjectDn) throws ServerException {
        com.vmware.identity.idm.SolutionUser idmSolutionUser;
        try {
            idmSolutionUser = this.idmClient.findSolutionUserByCertDn(tenant, certSubjectDn);
        } catch (Exception e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("idm error while retrieving solution user"), e);
        }

        if (idmSolutionUser == null || idmSolutionUser.getId() == null || idmSolutionUser.getCert() == null) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("solution user with specified cert subject dn not found"));
        }

        if (idmSolutionUser.isDisabled()) {
            throw new ServerException(OAuth2Error.ACCESS_DENIED.setDescription("solution user has been disabled or deleted"));
        }

        Date now = new Date();
        if (now.before(idmSolutionUser.getCert().getNotBefore()) || now.after(idmSolutionUser.getCert().getNotAfter())) {
            throw new ServerException(OAuth2Error.ACCESS_DENIED.setDescription("cert has expired"));
        }

        return new SolutionUser(idmSolutionUser.getId(), tenant, idmSolutionUser.getCert());
    }

    private static ErrorObject validateAssertionClaims(
            ReadOnlyJWTClaimsSet claimsSet,
            long assertionLifetimeMs,
            URL requestUrl,
            TenantInfo tenantInfo,
            ClientInfo clientInfo) {
        ErrorObject claimsError  = CommonValidator.validateBaseJwtClaims(claimsSet, (clientInfo != null) ? TokenClass.CLIENT_ASSERTION : TokenClass.SOLUTION_ASSERTION);
        String error = (claimsError == null) ? null : claimsError.getDescription();

        if (error == null && !Objects.equals(claimsSet.getIssuer(), claimsSet.getSubject())) {
            error = "assertion issuer and subject must be the same";
        }

        if (error == null && clientInfo != null && !Objects.equals(claimsSet.getIssuer(), clientInfo.getID().getValue())) {
            error = "client_assertion issuer must match client_id";
        }

        if (error == null) {
            // if we are behind rhttp proxy, the requestUrl will have http scheme instead of https
            String requestUrlHttps = requestUrl.toString().replaceFirst("http://", "https://");
            List<String> audience = claimsSet.getAudience();
            if (!(audience.size() == 1 && audience.get(0).equals(requestUrlHttps))) {
                error = "assertion audience does not match request URL";
            }
        }

        Date now = new Date();
        Date issueTime = claimsSet.getIssueTime();
        Date lowerBound = new Date(now.getTime() - tenantInfo.getClockToleranceMs() - assertionLifetimeMs);
        Date upperBound = new Date(now.getTime() + tenantInfo.getClockToleranceMs());
        if (error == null && (issueTime.before(lowerBound) || issueTime.after(upperBound))) {
            error = (clientInfo != null) ? "stale_client_assertion" : "stale_solution_assertion";
        }

        return (error == null) ? null : OAuth2Error.INVALID_CLIENT.setDescription(error);
    }
}