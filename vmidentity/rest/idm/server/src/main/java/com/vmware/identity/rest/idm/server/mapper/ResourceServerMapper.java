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
package com.vmware.identity.rest.idm.server.mapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

import org.apache.commons.lang.Validate;

import com.vmware.identity.idm.ResourceServer;
import com.vmware.identity.rest.core.server.exception.DTOMapperException;
import com.vmware.identity.rest.idm.data.ResourceServerDTO;

/**
 * Mapper utility to map objects from {@link ResourceServer} to {@link ResourceServerDTO} and vice-versa.
 *
 * @author Yehia Zayour
 */
public class ResourceServerMapper {

    public static ResourceServer getResourceServer(ResourceServerDTO resourceServerDTO) {
        Validate.notNull(resourceServerDTO, "resourceServerDTO");

        // name should start with rs_ because this is how oidc knows it's a resource server when it appears in the scope parameter
        String namePrefix = "rs_";
        String name = resourceServerDTO.getName();
        boolean validName =
                name != null &&
                name.startsWith(namePrefix) &&
                name.length() > namePrefix.length();
        if (!validName) {
            throw new DTOMapperException("name must start with " + namePrefix);
        }

        final Set<String> groupFilter = resourceServerDTO.getGroupFilter();
        if (groupFilter != null) {
            for (String groupFilterEntry : groupFilter) {
                if (groupFilterEntry.isEmpty()) {
                    throw new DTOMapperException("groupFilter entry is empty");
                }
            }
        }

        return new ResourceServer.Builder(name).groupFilter(groupFilter).build();
    }

    public static ResourceServerDTO getResourceServerDTO(ResourceServer resourceServer) {
        Validate.notNull(resourceServer, "resourceServer");
        return ResourceServerDTO.builder().
                withName(resourceServer.getName()).
                withGroupFilter(resourceServer.getGroupFilter()).build();
    }

    public static Collection<ResourceServerDTO> getResourceServerDTOs(Collection<ResourceServer> resourceServers) {
        Validate.notNull(resourceServers, "resourceServers");
        Collection<ResourceServerDTO> resourceServerDTOs = new ArrayList<ResourceServerDTO>();
        for (ResourceServer resourceServer : resourceServers) {
            resourceServerDTOs.add(getResourceServerDTO(resourceServer));
        }
        return resourceServerDTOs;
    }
}

