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

import org.apache.commons.lang3.Validate;

/**
 * @author Yehia Zayour
 */
public enum ScopeValue {
    ID_TOKEN_GROUPS("id_groups"),
    ID_TOKEN_GROUPS_FILTERED("id_groups_filtered"),
    ACCESS_TOKEN_GROUPS("at_groups"),
    ACCESS_TOKEN_GROUPS_FILTERED("at_groups_filtered"),
    RESOURCE_SERVER_ADMIN_SERVER("rs_admin_server");

    public static final String RESOURCE_SERVER_PREFIX = "rs_";

    private final String name;

    private ScopeValue(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public static boolean isDefined(String scopeValueName) {
        Validate.notEmpty(scopeValueName);

        boolean isDefined = false;
        for (ScopeValue scopeValue : ScopeValue.values()) {
            if (scopeValue.getName().equals(scopeValueName)) {
                isDefined = true;
                break;
            }
        }
        return isDefined;
    }
}