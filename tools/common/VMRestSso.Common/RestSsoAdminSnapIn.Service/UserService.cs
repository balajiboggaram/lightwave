/*
 * Copyright © 2012-2015 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

using System;
using System.Collections.Generic;
using System.Net;
using Vmware.Tools.RestSsoAdminSnapIn.Core.Serialization;
using Vmware.Tools.RestSsoAdminSnapIn.Core.Web;
using Vmware.Tools.RestSsoAdminSnapIn.Dto;

namespace Vmware.Tools.RestSsoAdminSnapIn.Service.User
{
    public class UserService
    {
        private readonly IWebRequestManager _webRequestManager;

        public UserService(IWebRequestManager webRequestManager)
        {
            _webRequestManager = webRequestManager;
        }

        public string Delete(ServerDto serverDto, string tenantName, UserDto user, Token token)
        {
            var name = Uri.EscapeDataString(user.Name + "@" + user.Domain);
            tenantName = Uri.EscapeDataString(tenantName);
            var url = string.Format(ServiceConfigManager.UserEndPoint, serverDto.Protocol, serverDto.ServerName, serverDto.Port, tenantName, name);
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            var requestConfig = new RequestSettings
            {
                Method = HttpMethod.Delete,
            };
            var headers = ServiceHelper.AddHeaders(ServiceConfigManager.JsonContentType);
            var json = "access_token=" + token.AccessToken + "&token_type=" + token.TokenType.ToString().ToLower();
            return _webRequestManager.GetResponse(url, requestConfig, headers, null, json);
        }

        public UserDto Create(ServerDto serverDto, string tenantName, UserDto userDto, Token token)
        {
            tenantName = Uri.EscapeDataString(tenantName);
            var json = JsonConvert.Serialize(userDto);
            var url = string.Format(ServiceConfigManager.UsersEndPoint, serverDto.Protocol, serverDto.ServerName, serverDto.Port, tenantName);
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            var requestConfig = new RequestSettings
            {
                Method = HttpMethod.Post,
            };
            var headers = ServiceHelper.AddHeaders();
            headers[HttpRequestHeader.Accept] = ServiceConfigManager.JsonContentType;
            headers[HttpRequestHeader.ContentType] = ServiceConfigManager.JsonContentType;
            json = "access_token=" + token.AccessToken + "&token_type=" + token.TokenType.ToString().ToLower() + "&" + json;
            var response = _webRequestManager.GetResponse(url, requestConfig, headers, null, json);
            return JsonConvert.Deserialize<UserDto>(response);
        }
        public UserDto Get(ServerDto serverDto, UserDto user, string tenantName, Token token)
        {
            var name = Uri.EscapeDataString(user.Name + "@" + user.Domain);
            tenantName = Uri.EscapeDataString(tenantName);
            var url = string.Format(ServiceConfigManager.GetUserEndPostPoint, serverDto.Protocol, serverDto.ServerName, serverDto.Port, tenantName, name);
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            var requestConfig = new RequestSettings
            {
                Method = HttpMethod.Post,
            };
            var headers = ServiceHelper.AddHeaders(ServiceConfigManager.JsonContentType);
            var postData = "access_token=" + token.AccessToken + "&token_type=" + token.TokenType.ToString().ToLower();
            var response = _webRequestManager.GetResponse(url, requestConfig, headers, null, postData);
            return JsonConvert.Deserialize<UserDto>(response);
        }
        public UserDto Update(ServerDto serverDto, string tenantName, UserDto user, Token token)
        {
            var name = Uri.EscapeDataString(user.Name + "@" + user.Domain);
            tenantName = Uri.EscapeDataString(tenantName);
            var json = JsonConvert.Serialize(user);
            var url = string.Format(ServiceConfigManager.UserEndPoint, serverDto.Protocol, serverDto.ServerName, serverDto.Port, tenantName, name);
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            var requestConfig = new RequestSettings
            {
                Method = HttpMethod.Put,
            };
            var headers = ServiceHelper.AddHeaders(ServiceConfigManager.JsonContentType);
            json = "access_token=" + token.AccessToken + "&token_type=" + token.TokenType.ToString().ToLower() + "&" + json;
            var response = _webRequestManager.GetResponse(url, requestConfig, headers, null, json);
            return JsonConvert.Deserialize<UserDto>(response);
        }

        public List<GroupDto> GetUserGroups(ServerDto serverDto, string tenantName, UserDto user, Token token)
        {
            var name = Uri.EscapeDataString(user.Name + "@" + user.Domain);
            tenantName = Uri.EscapeDataString(tenantName);
            var url = string.Format(ServiceConfigManager.GetUserGroupsPostEndPoint, serverDto.Protocol, serverDto.ServerName, serverDto.Port, tenantName, name);
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            var requestConfig = new RequestSettings
            {
                Method = HttpMethod.Post,
            };
            var headers = ServiceHelper.AddHeaders(ServiceConfigManager.JsonContentType);
            var postData = "access_token=" + token.AccessToken + "&token_type=" + token.TokenType.ToString().ToLower();
            var response = _webRequestManager.GetResponse(url, requestConfig, headers, null, postData);
            return JsonConvert.Deserialize<List<GroupDto>>(response);
        }

        public UserDto UpdatePassword(ServerDto serverDto, string tenantName, UserDto user, string currentPassword, string newPassword, Token token)
        {
            var name = Uri.EscapeDataString(user.Name + "@" + user.Domain);
            tenantName = Uri.EscapeDataString(tenantName);
            var url = string.Format(ServiceConfigManager.UserPasswordEndPoint, serverDto.Protocol, serverDto.ServerName, serverDto.Port, tenantName, name, currentPassword, newPassword);
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            var requestConfig = new RequestSettings
            {
                Method = HttpMethod.Put,
            };
            var headers = ServiceHelper.AddHeaders(ServiceConfigManager.JsonContentType);
            var json = "access_token=" + token.AccessToken + "&token_type=" + token.TokenType.ToString().ToLower();
            var result = _webRequestManager.GetResponse(url, requestConfig, headers, null, json);
            return JsonConvert.Deserialize<UserDto>(result);
        }
    }
}
