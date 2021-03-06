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
package com.vmware.identity.samlservice;

import org.apache.commons.lang.Validate;

import com.vmware.identity.diagnostics.DiagnosticsLoggerFactory;
import com.vmware.identity.diagnostics.IDiagnosticsLogger;
import com.vmware.identity.idm.client.CasIdmClient;
import com.vmware.identity.samlservice.impl.CasIdmAccessor;

/**
 * Factory which gives you IdmAccessor interface
 *
 */
public class DefaultIdmAccessorFactory implements IdmAccessorFactory {
	private static final IDiagnosticsLogger logger = DiagnosticsLoggerFactory.getLogger(DefaultIdmAccessorFactory.class);

	private CasIdmClient idmClient;

	/**
	 * Create factory
	 */
	public DefaultIdmAccessorFactory() {
		logger.debug("DefaultIdmAccessorFactory constructor");
		idmClient = new CasIdmClient(Shared.IDM_HOSTNAME);
		Validate.notNull(idmClient);
	}

	/**
	 * Return Idm Accessor object
	 * @return
	 */
	public IdmAccessor getIdmAccessor() {
		logger.debug("DefaultIdmAccessorFactory getIdmAccessor");
		Validate.notNull(idmClient);
		return new CasIdmAccessor(idmClient);
	}
}
