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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang3.Validate;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.vmware.identity.idm.ResourceServer;
import com.vmware.identity.idm.NoSuchResourceServerException;

/**
 * @author Yehia Zayour
 */
public class ServerInfoRetriever {
    private final IdmClient idmClient;

    public ServerInfoRetriever(IdmClient idmClient) {
        Validate.notNull(idmClient, "idmClient");
        this.idmClient = idmClient;
    }

    public AuthorizationServerInfo retrieveAuthorizationServerInfo() throws ServerException {
        String hostname = null; // for now hostname is not needed so we don't make an idm call for it

        String servicePrincipalName;
        try {
            servicePrincipalName = this.idmClient.getServerSPN();
        } catch (Exception e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("idm error while retrieving server info"), e);
        }

        return new AuthorizationServerInfo(hostname, servicePrincipalName);
    }

    public Set<ResourceServerInfo> retrieveResourceServerInfos(String tenant, Scope scope) throws ServerException {
        Validate.notEmpty(tenant, "tenant");
        Validate.notNull(scope, "scope");

        Set<ResourceServerInfo> resourceServerInfos = new HashSet<ResourceServerInfo>();

        // idm ResourceServer is only needed when group filtering is requested
        boolean makeIdmCall =
                scope.contains(ScopeValue.ID_TOKEN_GROUPS_FILTERED.getName()) ||
                scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS_FILTERED.getName());

        for (String scopeValue : scope.toStringList()) {
            if (scopeValue.startsWith(ScopeValue.RESOURCE_SERVER_PREFIX)) {
                String resourceServerName = scopeValue;
                ResourceServer idmResourceServer = null;
                if (makeIdmCall) {
                    try {
                        idmResourceServer = this.idmClient.getResourceServer(tenant, resourceServerName);
                    } catch (NoSuchResourceServerException e) {
                        idmResourceServer = null;
                    } catch (Exception e) {
                        throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("idm error while retrieving resource server info"), e);
                    }
                }
                Set<String> groupFilter = (idmResourceServer != null) ? idmResourceServer.getGroupFilter() : Collections.<String>emptySet();
                resourceServerInfos.add(new ResourceServerInfo(resourceServerName, groupFilter));
            }
        }

        return resourceServerInfos;
    }
}
