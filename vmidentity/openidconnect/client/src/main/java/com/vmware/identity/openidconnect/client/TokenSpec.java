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

import java.util.List;

/**
 * Token Spec
 *
 * @author Jun Sun
 */
public class TokenSpec {

    public static final TokenSpec EMPTY = new TokenSpec(new Builder());

    private final boolean refreshTokenRequested;
    private final GroupMembershipType idTokenGroupsRequested;
    private final GroupMembershipType accessTokenGroupsRequested;
    private final List<String> resouceServers;
    private final List<String> additionalScopeValues;

    private TokenSpec(Builder builder) {
        this.refreshTokenRequested = builder.refreshTokenRequested;
        this.idTokenGroupsRequested = builder.idTokenGroupsRequested;
        this.accessTokenGroupsRequested = builder.accessTokenGroupsRequested;
        this.resouceServers = builder.resouceServers;
        this.additionalScopeValues = builder.additionalScopeValues;
    }

    /**
     * Get refresh token request flag
     *
     * @return                          Boolean, refresh token request flag
     */
    public boolean isRefreshTokenRequested() {
        return this.refreshTokenRequested;
    }

    /**
     * Get id token group requested
     *
     * @return                          GroupMembershipType
     */
    public GroupMembershipType idTokenGroupsRequested() {
        return this.idTokenGroupsRequested;
    }

    /**
     * Get access token group requested
     *
     * @return                          GroupMembershipType
     */
    public GroupMembershipType accessTokenGroupsRequested() {
        return this.accessTokenGroupsRequested;
    }

    /**
     * Get resource servers
     *
     * @return                          A list of resource servers
     */
    public List<String> getResouceServers() {
        return this.resouceServers;
    }

    /**
     * Get additional scope values
     *
     * @return                          Additional scope values
     */
    public List<String> getAdditionalScopeValues() {
        return this.additionalScopeValues;
    }

    /**
     * Builder for TokenSpec class
     */
    public static class Builder {
        private boolean refreshTokenRequested;
        private GroupMembershipType idTokenGroupsRequested;
        private GroupMembershipType accessTokenGroupsRequested;
        private List<String> resouceServers;
        private List<String> additionalScopeValues;

        /**
         * Constructor
         */
        public Builder() {
        }

        /**
         * Set refresh token request flag
         *
         * @param refreshTokenRequested         Boolean, refresh token request flag
         * @return                              Builder object
         */
        public Builder refreshToken(boolean refreshTokenRequested) {
            this.refreshTokenRequested = refreshTokenRequested;
            return this;
        }

        /**
         * Set id token group request flag
         *
         * @param idTokenGroupsRequested        GroupMembershipType
         * @return                              Builder object
         */
        public Builder idTokenGroups(GroupMembershipType idTokenGroupsRequested) {
            this.idTokenGroupsRequested = idTokenGroupsRequested;
            return this;
        }

        /**
         * Set access token group request flag
         *
         * @param accessTokenGroupsRequested    GroupMembershipType
         * @return                              Builder object
         */
        public Builder accessTokenGroups(GroupMembershipType accessTokenGroupsRequested) {
            this.accessTokenGroupsRequested = accessTokenGroupsRequested;
            return this;
        }

        /**
         * Set resource servers
         *
         * @param resouceServers                A list of resource servers
         * @return                              Builder object
         */
        public Builder resouceServers(List<String> resouceServers) {
            this.resouceServers = resouceServers;
            return this;
        }

        /**
         * Set additional scope values
         *
         * @param additionalScopeValues         additional scope values
         * @return                              Builder object
         */
        public Builder additionalScopeValues(List<String> additionalScopeValues) {
            this.additionalScopeValues = additionalScopeValues;
            return this;
        }

        /**
         * Build TokenSpec object
         *
         * @return                              Builder object
         */
        public TokenSpec build() {
            return new TokenSpec(this);
        }
    }
}