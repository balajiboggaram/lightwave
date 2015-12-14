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
import java.util.Set;

import org.apache.commons.lang3.Validate;

import com.nimbusds.oauth2.sdk.id.ClientID;

/**
 * @author Yehia Zayour
 */
public class ClientInfo {
    private final ClientID id;
    private final Set<URI> redirectUris;
    private final Set<URI> postLogoutRedirectUris;
    private final URI logoutUri;
    private final String certSubjectDn;

    public ClientInfo(
            ClientID id,
            Set<URI> redirectUris,
            Set<URI> postLogoutRedirectUris,
            URI logoutUri,
            String certSubjectDn) {
        Validate.notNull(id, "id");
        Validate.notEmpty(redirectUris, "redirectUris");
        Validate.notNull(postLogoutRedirectUris, "postLogoutRedirectUris");
        // logoutUri can be null
        // certSubjectDn can be null

        this.id = id;
        this.redirectUris = redirectUris;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.logoutUri = logoutUri;
        this.certSubjectDn = certSubjectDn;
    }

    public ClientID getID() {
        return this.id;
    }

    public Set<URI> getRedirectUris() {
        return this.redirectUris;
    }

    public Set<URI> getPostLogoutRedirectUris() {
        return this.postLogoutRedirectUris;
    }

    public URI getLogoutUri() {
        return this.logoutUri;
    }

    public String getCertSubjectDn() {
        return this.certSubjectDn;
    }
}