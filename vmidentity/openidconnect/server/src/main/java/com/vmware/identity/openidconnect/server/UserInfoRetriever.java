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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.Validate;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.vmware.identity.idm.Attribute;
import com.vmware.identity.idm.AttributeValuePair;
import com.vmware.identity.idm.InvalidPrincipalException;
import com.vmware.identity.idm.KnownSamlAttributes;

/**
 * @author Yehia Zayour
 */
public class UserInfoRetriever {
    private final IdmClient idmClient;

    public UserInfoRetriever(IdmClient idmClient) {
        Validate.notNull(idmClient, "idmClient");
        this.idmClient = idmClient;
    }

    public UserInfo retrieveUserInfo(User user, Scope scope, Set<ResourceServerInfo> resourceServerInfos) throws ServerException {
        Validate.notNull(user, "user");
        Validate.notNull(scope, "scope");
        Validate.notNull(resourceServerInfos, "resourceServerInfos");

        if (!isEnabled(user)) {
            throw new ServerException(OAuth2Error.ACCESS_DENIED.setDescription("user has been disabled or deleted"));
        }

        List<String> groupMembership = null;
        Set<String> groupMembershipFiltered = null;
        String adminServerRole = null;
        String givenName = null;
        String familyName = null;

        if (user instanceof PersonUser) {
            com.vmware.identity.idm.PersonUser idmPersonUser;
            try {
                idmPersonUser = this.idmClient.findPersonUser(user.getTenant(), user.getPrincipalId());
            } catch (Exception e) {
                throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("idm error while retrieving person user"), e);
            }
            if (idmPersonUser == null) {
                throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("person user with specified id not found"));
            }
            givenName = idmPersonUser.getDetail().getFirstName();
            familyName = idmPersonUser.getDetail().getLastName();
        }

        if (scope.contains(ScopeValue.RESOURCE_SERVER_ADMIN_SERVER.getName())) {
            adminServerRole = computeAdminServerRole(user);
        }

        if (
                scope.contains(ScopeValue.ID_TOKEN_GROUPS.getName()) ||
                scope.contains(ScopeValue.ID_TOKEN_GROUPS_FILTERED.getName()) ||
                scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS.getName()) ||
                scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS_FILTERED.getName())) {
            groupMembership = computeGroupMembership(user);
        }

        boolean filteredGroupsRequested =
                scope.contains(ScopeValue.ID_TOKEN_GROUPS_FILTERED.getName()) ||
                scope.contains(ScopeValue.ACCESS_TOKEN_GROUPS_FILTERED.getName());

        boolean shouldComputeFilteredGroups = false;
        if (filteredGroupsRequested && !resourceServerInfos.isEmpty()) {
            boolean emptyFilterFound = false;
            for (ResourceServerInfo rsInfo : resourceServerInfos) {
                if (rsInfo.getGroupFilter().isEmpty()) {
                    emptyFilterFound = true;
                    break;
                }
            }
            if (!emptyFilterFound) {
                shouldComputeFilteredGroups = true;
            }
        }

        if (shouldComputeFilteredGroups) {
            groupMembershipFiltered = computeGroupMembershipFiltered(groupMembership, resourceServerInfos);
        }

        return new UserInfo(groupMembership, groupMembershipFiltered, adminServerRole, givenName, familyName);
    }

    public boolean isMemberOfGroup(User user, String group) throws ServerException {
        Validate.notNull(user, "user");
        Validate.notEmpty(group, "group");
        try {
            return this.idmClient.isMemberOfSystemGroup(user.getTenant(), user.getPrincipalId(), group);
        } catch (Exception e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("idm error while checking is member of system group"), e);
        }
    }

    private boolean isEnabled(User user) throws ServerException {
        boolean enabled;
        try {
            enabled = this.idmClient.isActive(user.getTenant(), user.getPrincipalId());
        } catch (InvalidPrincipalException e) {
            enabled = false;
        } catch (Exception e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("idm error while checking isActive status"), e);
        }
        return enabled;
    }

    private Set<String> computeGroupMembershipFiltered(List<String> groupMembership, Set<ResourceServerInfo> resourceServerInfos) {
        // 1. result = {union of all filters}
        Set<String> result = new HashSet<String>();
        for (ResourceServerInfo rsInfo : resourceServerInfos) {
            assert !rsInfo.getGroupFilter().isEmpty();
            Set<String> groupFilterLowerCase = toLowerCase(rsInfo.getGroupFilter());
            result.addAll(groupFilterLowerCase);
        }

        // 2. result = intersection of {union of all filters} with groupMembership
        Set<String> groupMembershipLowerCase = toLowerCase(groupMembership);
        result.retainAll(groupMembershipLowerCase);
        return result;
    }

    private List<String> computeGroupMembership(User user) throws ServerException {
        Collection<AttributeValuePair> attributeValuePairs;
        try {
            attributeValuePairs = this.idmClient.getAttributeValues(
                    user.getTenant(),
                    user.getPrincipalId(),
                    Collections.singleton(new Attribute(KnownSamlAttributes.ATTRIBUTE_USER_GROUPS)));
        } catch (Exception e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("idm error while retrieving group membership"), e);
        }
        assert attributeValuePairs != null && attributeValuePairs.size() == 1;
        AttributeValuePair attributeValuePair = attributeValuePairs.iterator().next();
        return attributeValuePair.getValues();
    }

    private String computeAdminServerRole(User user) throws ServerException {
        String role;
        if (isMemberOfGroup(user, "administrators")) {
            role = "Administrator";
        } else if (isMemberOfGroup(user, "systemconfiguration.administrators")) {
            role = "ConfigurationUser";
        } else if (isMemberOfGroup(user, "users")) {
            role = "RegularUser";
        } else {
            role = "GuestUser";
        }
        return role;
    }

    private static Set<String> toLowerCase(Collection<String> collection) {
        Set<String> result = new HashSet<String>();
        for (String element : collection) {
            result.add(element.toLowerCase());
        }
        return result;
    }
}
