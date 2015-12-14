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

import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.vmware.identity.openidconnect.common.GssTicketGrant;
import com.vmware.identity.openidconnect.common.SolutionUserCredentialsGrant;

/**
 * @author Jun Sun
 * @author Yehia Zayour
 */
public final class Profile {

    public static final List<SubjectType> SUBJECT_TYPES = Arrays.asList(
            SubjectType.PUBLIC);

    public static final List<ResponseType> RESPONSE_TYPES = Arrays.asList(
            new ResponseType(ResponseType.Value.CODE),
            new ResponseType(OIDCResponseTypeValue.ID_TOKEN),
            new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN));

    public static final List<JWSAlgorithm> ID_TOKEN_JWS_ALGS = Arrays.asList(
            JWSAlgorithm.RS256);

    public static final List<GrantType> GRANT_TYPES = Arrays.asList(
            GrantType.IMPLICIT,
            AuthorizationCodeGrant.GRANT_TYPE,
            RefreshTokenGrant.GRANT_TYPE,
            ResourceOwnerPasswordCredentialsGrant.GRANT_TYPE,
            ClientCredentialsGrant.GRANT_TYPE,
            SolutionUserCredentialsGrant.GRANT_TYPE,
            GssTicketGrant.GRANT_TYPE);

    public static final List<ClientAuthenticationMethod> TOKEN_ENDPOINT_AUTH_METHODS = Arrays.asList(
            ClientAuthenticationMethod.PRIVATE_KEY_JWT);

    public static final List<JWSAlgorithm> TOKEN_ENDPOINT_JWS_ALGS = Arrays.asList(
            JWSAlgorithm.RS256);

    public static final Scope SCOPES = new Scope(
            "openid",
            "offline_access",
            "id_groups",
            "id_groups_filtered",
            "at_groups",
            "at_groups_filtered",
            "rs_admin_server");

    public static final List<String> CLAIMS = Arrays.asList(
            "sub",
            "exp",
            "aud",
            "iss",
            "iat",
            "jti",
            "given_name",
            "family_name",
            "token_class",
            "token_type",
            "nonce",
            "hotk",
            "sid",
            "act_as",
            "tenant",
            "client_id",
            "scope",
            "groups",
            "admin_server_role");
}