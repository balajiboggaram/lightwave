﻿/*
 * Copyright © 2012-2015 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *·
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using VMDirInterop.Interfaces;
using VMDirInterop.LDAPConstants;
using VMDirInterop.LDAPExceptions;

namespace VMDirInterop.LDAP
{
    public class LdapConnection : ILdapConnection
    {
        private IntPtr _connection = IntPtr.Zero;
        private IntPtr _result = IntPtr.Zero;

        public LdapConnection()
        {
            _connection = IntPtr.Zero;
        }

        public LdapConnection(IntPtr ldapPointer)
            : this()
        {
            _connection = ldapPointer;
        }

        public static ILdapConnection LdapInit(string HostName, int PortNumber)
        {
            var ldapPointer = LdapClientLibrary.ldap_init(HostName, PortNumber);
            return new LdapConnection(ldapPointer);
        }

        public void LdapSimpleBindS(string dn, string passwd)
        {
            SetVersion(LDAPOption.LDAP_VERSION);
            var returnError = LdapClientLibrary.ldap_simple_bind_s(this._connection, dn, passwd);
            ErrorCheckerHelper.Validate(returnError);
        }

        public void SetVersion(int version)
        {
            IntPtr ptrVersion = Marshal.AllocHGlobal(Marshal.SizeOf(version));
            Marshal.WriteInt32(ptrVersion, version);
            try
            {
                SetOption(LDAPOption.LDAP_OPT_PROTOCOL_VERSION, ptrVersion);
            }
            finally
            {
                Marshal.FreeHGlobal(ptrVersion);
            }
        }

        public void SetOption(int option, IntPtr ptrVersion)
        {
            var returnError = LdapClientLibrary.ldap_set_option(this._connection, (int)option, ptrVersion);
            ErrorCheckerHelper.Validate(returnError);
        }

        public void VmDirSafeLDAPBind(string host, string upn, string passwd)
        {
            SetVersion(LDAPOption.LDAP_VERSION);
            var VmDirError = LdapClientLibrary.VmDirSafeLDAPBind(out this._connection, host, upn, passwd);
            var returnError = LdapError.VmDirMapLdapError((int)VmDirError);
            ErrorCheckerHelper.Validate(returnError);
        }

        public ILdapMessage LdapSearchExtS(string querybase, int scope, string filter, string[] attrs, int attrsonly, IntPtr timeout, int sizelimit)
        {
            ILdapMessage message;
            var returnError = LdapClientLibrary.ldap_search_ext_s(this._connection, querybase, scope, filter, attrs, 0, 0, 0, timeout, sizelimit, ref this._result);
            ErrorCheckerHelper.Validate(returnError);
            message = new LdapMessage(this, _result);
            return message;
        }

        public void AddObject(string dn, LdapMod[] attrs)
        {
            IntPtr basednPtr = IntPtr.Zero;
            basednPtr = Marshal.StringToHGlobalAnsi(dn);

            IntPtr[] umattrs = new IntPtr[attrs.Length + 1];
            for (int i = 0; i < attrs.Length; i++)
            {
                umattrs[i] = attrs[i].convertToUnmanaged();
            }

            umattrs[attrs.Length] = IntPtr.Zero; /* NULL Termination */

            var returnError = LdapClientLibrary.ldap_add_ext_s(this._connection, basednPtr, umattrs, null, null);

            for (int i = 0; i < attrs.Length; i++)
            {
                attrs[i].Free();
                Marshal.FreeHGlobal(umattrs[i]);
            }

            Marshal.FreeHGlobal(basednPtr);

            ErrorCheckerHelper.Validate((int)returnError);

            return;
        }


        public void ModifyObject(string basedn, LdapMod[] attrs)
        {
            IntPtr basednPtr = IntPtr.Zero;
            basednPtr = Marshal.StringToHGlobalAnsi(basedn);

            IntPtr[] umattrs = new IntPtr[attrs.Length + 1];
            for (int i = 0; i < attrs.Length; i++)
            {
                umattrs[i] = attrs[i].convertToUnmanaged();
            }

            umattrs[attrs.Length] = IntPtr.Zero; /* NULL Termination */

            var returnError = LdapClientLibrary.ldap_modify_ext_s(this._connection, basednPtr, umattrs, null, null);

            for (int i = 0; i < attrs.Length; i++)
            {
                attrs[i].Free();
                Marshal.FreeHGlobal(umattrs[i]);
            }

            Marshal.FreeHGlobal(basednPtr);

            ErrorCheckerHelper.Validate((int)returnError);
        }


        public void DeleteObject(string dn)
        {
            var returnError = LdapClientLibrary.ldap_delete_ext_s(this._connection, dn, null, null);
            ErrorCheckerHelper.Validate((int)returnError);
        }


        public void CleanSearch()
        {
            LdapClientLibrary.ldap_msgfree(this._result);
        }

        public void LdapUnbindS()
        {
            var returnError = LdapClientLibrary.ldap_unbind_s(this._connection);
            ErrorCheckerHelper.Validate(returnError);
        }

        public IntPtr GetIntPtr()
        {
            return _connection;
        }

    }

}
