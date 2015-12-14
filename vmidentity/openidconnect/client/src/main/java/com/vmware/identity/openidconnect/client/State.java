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

import org.apache.commons.lang3.Validate;

/**
 * State in OIDC work flow. If used, the state in response should match with the state in original request.
 *
 * @author Jun Sun
 */
public class State {

    private final String value;

    /**
     * Constructor
     *
     * @param value                     state value
     */
    public State(String value) {
        Validate.notEmpty(value, "value");

        this.value = value;
    }

    /**
     * Get state value
     *
     * @return                          String value of state
     */
    public String getValue() {
        return this.value;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object object) {
        return object instanceof State && this.getValue().equals(((State) object).getValue());
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return this.value.hashCode();
    }
}