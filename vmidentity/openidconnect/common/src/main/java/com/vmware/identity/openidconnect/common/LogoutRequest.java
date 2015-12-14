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

package com.vmware.identity.openidconnect.common;

import java.net.URI;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.id.State;

/**
 * @author Yehia Zayour
 */
public class LogoutRequest extends com.nimbusds.openid.connect.sdk.LogoutRequest {
    private static final String HTML_FORM =
            "<html>" +
            "    <head>" +
            "        <script language=\"JavaScript\" type=\"text/javascript\">" +
            "            function load(){ document.getElementById('LogoutRequestForm').submit(); }" +
            "        </script>" +
            "    </head>" +
            "    <body onload=\"load()\">" +
            "        <form method=\"post\" id=\"LogoutRequestForm\" action=\"%s\">" +
            "            %s" +
            "            <input type=\"submit\" value=\"Submit\" style=\"position:absolute; left:-9999px; width:1px; height:1px;\" />" +
            "        </form>" +
            "    </body>" +
            "</html>";

    private static final String HTML_FORM_PARAMETER = "<input type=\"hidden\" name=\"%s\" value=\"%s\" />";

    private final SignedJWT clientAssertion;
    private final CorrelationID correlationId;

    public LogoutRequest(
            URI uri,
            IDToken idTokenHint,
            URI postLogoutRedirectUri,
            State state,
            SignedJWT clientAssertion,
            CorrelationID correlationId) {
        super(uri, idTokenHint, postLogoutRedirectUri, state);

        Validate.notNull(uri, "uri");
        Validate.notNull(idTokenHint, "idTokenHint");

        this.clientAssertion = clientAssertion;
        this.correlationId = correlationId;
    }

    public SignedJWT getClientAssertion() {
        return this.clientAssertion;
    }

    public CorrelationID getCorrelationID() {
        return this.correlationId;
    }

    @Override
    public IDToken getIDTokenHint() {
        return (IDToken) super.getIDTokenHint();
    }

    @Override
    public Map<String, String> toParameters() throws SerializeException {
        Map<String, String> result = super.toParameters();
        if (this.clientAssertion != null) {
            result.put("client_assertion", this.clientAssertion.serialize());
        }
        if (this.correlationId != null) {
            result.put("correlation_id", this.correlationId.getValue());
        }
        return result;
    }

    public String toHtmlForm() throws SerializeException {
        Map<String, String> parameters = this.toParameters();
        StringBuilder formParameters = new StringBuilder();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            String parameterName = entry.getKey();
            String parameterValue = entry.getValue();
            formParameters.append(String.format(HTML_FORM_PARAMETER, parameterName, parameterValue));
        }

        String formAction = super.getEndpointURI().toString();
        return String.format(HTML_FORM, formAction, formParameters.toString());
    }

    public static LogoutRequest parse(HttpRequest httpRequest) throws ParseException {
        Validate.notNull(httpRequest, "httpRequest");

        Map<String, String> parameters = httpRequest.getParameters();
        com.nimbusds.openid.connect.sdk.LogoutRequest nimbusRequest = com.nimbusds.openid.connect.sdk.LogoutRequest.parse(httpRequest.getRequestUri(), parameters);

        if (!(nimbusRequest.getIDTokenHint() instanceof SignedJWT)) {
            throw new ParseException("id_token_hint must be a signed jwt");
        }

        if (nimbusRequest.getPostLogoutRedirectionURI() != null && !CommonUtils.isValidUri(nimbusRequest.getPostLogoutRedirectionURI())) {
            throw new ParseException("invalid post_logout_redirect_uri");
        }

        SignedJWT clientAssertion = null;
        String clientAssertionString = parameters.get("client_assertion");
        if (!StringUtils.isBlank(clientAssertionString)) {
            try {
                clientAssertion = SignedJWT.parse(clientAssertionString);
            } catch (java.text.ParseException e) {
                throw new ParseException("failed to parse client_assertion parameter: " + e.getMessage());
            }
        }

        CorrelationID correlationId = null;
        String correlationIdString = parameters.get("correlation_id");
        if (!StringUtils.isBlank(correlationIdString)) {
            correlationId = new CorrelationID(correlationIdString);
        }

        return new LogoutRequest(
                nimbusRequest.getEndpointURI(),
                new IDToken((SignedJWT) nimbusRequest.getIDTokenHint()),
                nimbusRequest.getPostLogoutRedirectionURI(),
                nimbusRequest.getState(),
                clientAssertion,
                correlationId);
    }
}