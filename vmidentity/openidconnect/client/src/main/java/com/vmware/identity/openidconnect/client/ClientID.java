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

package com.vmware.identity.openidconnect.client;

import java.io.Serializable;

import org.apache.commons.lang3.Validate;

/**
 * Client Id.
 *
 * @author Jun Sun
 */
public class ClientID implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String value;

    /**
     * Constructor
     *
     * @param value             String value of client Id
     */
    public ClientID(String value) {
        Validate.notEmpty(value, "value");

        this.value = value;
    }

    /**
     * Get client Id
     *
     * @return                  String value of client Id
     */
    public String getValue() {
        return this.value;
    }
}
