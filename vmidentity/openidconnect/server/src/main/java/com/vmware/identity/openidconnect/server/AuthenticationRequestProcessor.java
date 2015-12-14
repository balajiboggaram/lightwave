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

import java.util.Locale;
import java.util.Set;

import javax.servlet.http.Cookie;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.springframework.context.MessageSource;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.vmware.identity.diagnostics.DiagnosticsLoggerFactory;
import com.vmware.identity.diagnostics.IDiagnosticsLogger;
import com.vmware.identity.idm.GSSResult;
import com.vmware.identity.openidconnect.common.AuthenticationErrorResponse;
import com.vmware.identity.openidconnect.common.AuthenticationRequest;
import com.vmware.identity.openidconnect.common.AuthenticationSuccessResponse;
import com.vmware.identity.openidconnect.common.HttpRequest;
import com.vmware.identity.openidconnect.common.IDToken;
import com.vmware.identity.openidconnect.common.SessionID;

/**
 * @author Yehia Zayour
 */
public class AuthenticationRequestProcessor {
    private static final long REQUEST_LIFETIME_MS = 50 * 60 * 1000L; // 50 minutes, to allow for user to get login form, then login later

    private static final String REQUEST_LOGIN_PARAMETER = "CastleAuthorization";
    private static final String RESPONSE_AUTHZ_HEADER   = "CastleAuthorization";
    private static final String RESPONSE_ERROR_HEADER   = "CastleError";
    private static final String GSS_LOGIN_METHOD        = "Negotiate";
    private static final String PASSWORD_LOGIN_METHOD   = "Basic";

    private static final IDiagnosticsLogger logger = DiagnosticsLoggerFactory.getLogger(AuthenticationRequestProcessor.class);

    private final TenantInfoRetriever tenantInfoRetriever;
    private final ClientInfoRetriever clientInfoRetriever;
    private final ServerInfoRetriever serverInfoRetriever;
    private final UserInfoRetriever userInfoRetriever;
    private final PersonUserAuthenticator personUserAuthenticator;
    private final SolutionUserAuthenticator solutionUserAuthenticator;

    private final AuthorizationCodeManager authzCodeManager;
    private final SessionManager sessionManager;
    private final MessageSource messageSource;
    private final Model model;
    private final Locale locale;
    private final HttpRequest httpRequest;
    private final String tenant;

    private TenantInfo tenantInfo;
    private ClientInfo clientInfo;
    private AuthenticationRequest authnRequest;

    public AuthenticationRequestProcessor(
            IdmClient idmClient,
            AuthorizationCodeManager authzCodeManager,
            SessionManager sessionManager,
            MessageSource messageSource,
            Model model,
            Locale locale,
            HttpRequest httpRequest,
            String tenant) {
        this.tenantInfoRetriever = new TenantInfoRetriever(idmClient);
        this.clientInfoRetriever = new ClientInfoRetriever(idmClient);
        this.serverInfoRetriever = new ServerInfoRetriever(idmClient);
        this.userInfoRetriever = new UserInfoRetriever(idmClient);
        this.personUserAuthenticator = new PersonUserAuthenticator(idmClient);
        this.solutionUserAuthenticator = new SolutionUserAuthenticator(idmClient);

        this.authzCodeManager = authzCodeManager;
        this.sessionManager = sessionManager;
        this.messageSource = messageSource;
        this.model = model;
        this.locale = locale;
        this.httpRequest = httpRequest;
        this.tenant = tenant;

        // set by initialize()
        this.tenantInfo = null;
        this.clientInfo = null;
        this.authnRequest = null;
    }

    public Pair<ModelAndView, HttpResponse> process() {
        try {
            initialize();
        } catch (ServerException e) {
            Shared.logFailedRequest(logger, e);
            return Pair.of((ModelAndView) null, HttpResponse.error(e));
        }

        ErrorObject validationError = validate();
        if (validationError != null) {
            Shared.logFailedRequest(logger, validationError);
            AuthenticationErrorResponse authnErrorResponse = authnErrorResponse(validationError);
            return Pair.of((ModelAndView) null, HttpResponse.success(authnErrorResponse));
        }

        try {
            authenticateClient();
        } catch (ServerException e) {
            Shared.logFailedRequest(logger, e);
            AuthenticationErrorResponse authnErrorResponse = authnErrorResponse(e.getErrorObject());
            return Pair.of((ModelAndView) null, HttpResponse.success(authnErrorResponse));
        }

        Triple<PersonUser, SessionID, Boolean> loginResult;
        try {
            loginResult = processLogin();
        } catch (ServerException e) {
            Shared.logFailedRequest(logger, e);
            return Pair.of((ModelAndView) null, HttpResponse.error(e));
        }

        PersonUser personUser = loginResult.getLeft();
        SessionID sessionId   = loginResult.getMiddle();
        Boolean addSession    = loginResult.getRight();

        if (personUser == null) {
            AuthorizationServerInfo authzServerInfo;
            try {
                authzServerInfo = this.serverInfoRetriever.retrieveAuthorizationServerInfo();
            } catch (ServerException e) {
                Shared.logFailedRequest(logger, e);
                return Pair.of((ModelAndView) null, HttpResponse.error(e));
            }
            ModelAndView loginForm = generateLoginForm(authzServerInfo.getServicePrincipalName());
            return Pair.of(loginForm, (HttpResponse) null);
        }

        AuthenticationResponse authnResponse;
        try {
            authnResponse = (this.authnRequest.getResponseType().contains(ResponseType.Value.CODE)) ?
                    processAuthzCodeResponse(personUser, sessionId) :
                    processIdTokenResponse(personUser, sessionId);
        } catch (ServerException e) {
            Shared.logFailedRequest(logger, e);
            authnResponse = authnErrorResponse(e.getErrorObject());
        }

        Cookie sessionCookie = null;
        if (authnResponse instanceof AuthenticationSuccessResponse) {
            if (addSession) {
                this.sessionManager.add(sessionId, personUser, this.clientInfo);
                sessionCookie = sessionCookie(sessionId);
            } else {
                this.sessionManager.update(sessionId, this.clientInfo);
            }
        }
        return Pair.of((ModelAndView) null, HttpResponse.success(authnResponse, sessionCookie));
    }

    private void initialize() throws ServerException {
        try {
            this.authnRequest = AuthenticationRequest.parse(this.httpRequest);
        } catch (ParseException e) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription(e.getMessage()), e);
        }

        String tenantName = this.tenant;
        if (tenantName == null) {
            tenantName = this.tenantInfoRetriever.getDefaultTenantName();
        }
        this.tenantInfo = this.tenantInfoRetriever.retrieveTenantInfo(tenantName);
        this.clientInfo = this.clientInfoRetriever.retrieveClientInfo(tenantName, this.authnRequest.getClientID());

        if (!this.clientInfo.getRedirectUris().contains(this.authnRequest.getRedirectionURI())) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("unregistered redirect_uri"));
        }
    }

    private void authenticateClient() throws ServerException {
        if (this.clientInfo.getCertSubjectDn() != null) {
            if (this.authnRequest.getClientAssertion() != null) {
                this.solutionUserAuthenticator.authenticateByClientAssertion(
                        this.authnRequest.getClientAssertion(),
                        REQUEST_LIFETIME_MS,
                        this.httpRequest.getRequestUrl(),
                        this.tenantInfo,
                        this.clientInfo);
            } else {
                throw new ServerException(OAuth2Error.INVALID_CLIENT.setDescription("client_assertion parameter is required since client has registered a cert"));
            }
        }
    }

    private Triple<PersonUser, SessionID, Boolean> processLogin() throws ServerException {
        PersonUser personUser = null;
        SessionID sessionId = null;
        Boolean addSession = Boolean.FALSE;

        String sessionIdString = this.httpRequest.getCookieValue(Shared.getSessionCookieName(this.tenantInfo.getName()));
        if (sessionIdString != null) {
            sessionId = new SessionID(sessionIdString);
            SessionManager.Entry entry = this.sessionManager.get(sessionId);
            if (entry != null) {
                personUser = entry.getPersonUser();
                return Triple.of(personUser, sessionId, addSession);
            }
        }

        String loginString = this.httpRequest.getParameters().get(REQUEST_LOGIN_PARAMETER);
        if (loginString != null) {
            if (loginString.startsWith(PASSWORD_LOGIN_METHOD)) {
                personUser = processPasswordLogin(loginString);
            } else if (loginString.startsWith(GSS_LOGIN_METHOD)) {
                personUser = processGssLogin(loginString);
            } else {
                throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("invalid login method"), errorHeader("BadRequest"));
            }
            sessionId = new SessionID();
            addSession = Boolean.TRUE;
        }

        return Triple.of(personUser, sessionId, addSession);
    }

    private PersonUser processPasswordLogin(String loginString) throws ServerException {
        PersonUser personUser;

        // CastleAuthorization=Basic base64(username:password)
        String[] parts = loginString.split(" ");
        if (parts.length != 2) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("malformed password login string"), errorHeader("BadRequest"));
        }
        String unp = (new Base64(parts[1])).decodeToString();

        int index = unp.indexOf(':');
        if (!(0 < index && index < unp.length() - 1)) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("malformed username:password in login string"), errorHeader("BadRequest"));
        }

        String username = unp.substring(0, index);
        String password = unp.substring(index + 1);

        try {
            personUser = this.personUserAuthenticator.authenticate(this.tenantInfo.getName(), username, password);
        } catch (InvalidCredentialsException e) {
            throw new ServerException(new ErrorObject("Unauthorized", "Incorrect username/password", HttpResponse.SC_UNAUTHORIZED), e, errorHeader("Unauthorized"));
        } catch (ServerException e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("error while authenticating username/password"), e, errorHeader("Responder"));
        }

        return personUser;
    }

    private PersonUser processGssLogin(String loginString) throws ServerException {
        PersonUser personUser;

        // CastleAuthorization=Negotiate contextId base64(token)
        String[] parts = loginString.split(" ");
        if (parts.length != 3) {
            throw new ServerException(OAuth2Error.INVALID_REQUEST.setDescription("malformed gss login string"), errorHeader("BadRequest"));
        }
        String contextId = parts[1];
        byte[] gssTicketBytes = (new Base64(parts[2]).decode());

        GSSResult gssResult;
        try {
            gssResult = this.personUserAuthenticator.authenticate(this.tenantInfo.getName(), contextId, gssTicketBytes);
        } catch (InvalidCredentialsException e) {
            throw new ServerException(new ErrorObject("Unauthorized", "invalid gss token", HttpResponse.SC_UNAUTHORIZED), e, errorHeader("Unauthorized"));
        } catch (ServerException e) {
            throw new ServerException(OAuth2Error.SERVER_ERROR.setDescription("error while doing gss authn"), e, errorHeader("Responder"));
        }

        if (gssResult.complete()) {
            personUser = new PersonUser(gssResult.getPrincipalId(), this.tenantInfo.getName());
        } else {
            String serverLeg64 = Base64.encode(gssResult.getServerLeg()).toString();
            String responseAuthzHeaderValue = String.format("%s %s %s", GSS_LOGIN_METHOD, contextId, serverLeg64);
            Header responseAuthzHeader = new Header(RESPONSE_AUTHZ_HEADER, responseAuthzHeaderValue);
            throw new ServerException(new ErrorObject("Unauthorized", "continue Negotiate required", HttpResponse.SC_UNAUTHORIZED), responseAuthzHeader, errorHeader("Unauthorized"));
        }

        return personUser;
    }

    private AuthenticationSuccessResponse processAuthzCodeResponse(PersonUser personUser, SessionID sessionId) {
        AuthorizationCode authzCode = new AuthorizationCode();

        this.authzCodeManager.add(
                authzCode,
                personUser,
                sessionId,
                this.authnRequest);

        return new AuthenticationSuccessResponse(
                this.authnRequest.getRedirectionURI(),
                authzCode,
                (IDToken) null,
                (AccessToken) null,
                this.authnRequest.getState(),
                this.authnRequest.getResponseMode(),
                httpRequest.getParameters().get(REQUEST_LOGIN_PARAMETER) != null /* isAjaxRequest */);
    }

    private AuthenticationSuccessResponse processIdTokenResponse(PersonUser personUser, SessionID sessionId) throws ServerException {
        Set<ResourceServerInfo> resourceServerInfos = this.serverInfoRetriever.retrieveResourceServerInfos(this.tenantInfo.getName(), this.authnRequest.getScope());
        UserInfo userInfo = this.userInfoRetriever.retrieveUserInfo(personUser, this.authnRequest.getScope(), resourceServerInfos);

        TokenIssuer tokenIssuer = new TokenIssuer(
                personUser,
                (SolutionUser) null,
                userInfo,
                this.tenantInfo,
                this.authnRequest.getScope(),
                this.authnRequest.getNonce(),
                this.authnRequest.getClientID(),
                sessionId);

        IDToken idToken = tokenIssuer.issueIdToken();
        AccessToken accessToken = null;
        if (this.authnRequest.getResponseType().contains(ResponseType.Value.TOKEN)) {
            accessToken = tokenIssuer.issueAccessToken();
        }

        return new AuthenticationSuccessResponse(
                this.authnRequest.getRedirectionURI(),
                (AuthorizationCode) null,
                idToken,
                accessToken,
                this.authnRequest.getState(),
                this.authnRequest.getResponseMode(),
                httpRequest.getParameters().get(REQUEST_LOGIN_PARAMETER) != null /* isAjaxRequest */);
    }

    private ErrorObject validate() {
        ErrorObject error = null;

        ResponseType responseType = this.authnRequest.getResponseType();
        int size = responseType.size();
        boolean responseTypeSupported =
                (size == 1 && responseType.contains(ResponseType.Value.CODE)) ||
                (size == 1 && responseType.contains(OIDCResponseTypeValue.ID_TOKEN)) ||
                (size == 2 && responseType.contains(OIDCResponseTypeValue.ID_TOKEN) && responseType.contains(ResponseType.Value.TOKEN));

        if (!responseTypeSupported) {
            error = OAuth2Error.UNSUPPORTED_RESPONSE_TYPE;
        }

        if (error == null) {
            GrantType grantType = responseType.contains(ResponseType.Value.CODE) ? AuthorizationCodeGrant.GRANT_TYPE : GrantType.IMPLICIT;
            error = CommonValidator.validateScope(this.authnRequest.getScope(), grantType);
        }

        return error;
    }

    private AuthenticationErrorResponse authnErrorResponse(ErrorObject error) {
        return new AuthenticationErrorResponse(
                this.authnRequest.getRedirectionURI(),
                error,
                this.authnRequest.getResponseType(),
                this.authnRequest.getState(),
                this.authnRequest.getResponseMode(),
                httpRequest.getParameters().get(REQUEST_LOGIN_PARAMETER) != null /* isAjaxRequest */);
    }

    private Cookie sessionCookie(SessionID sessionId) {
        Cookie sessionCookie = new Cookie(Shared.getSessionCookieName(this.tenantInfo.getName()), sessionId.getValue());
        sessionCookie.setPath("/openidconnect");
        sessionCookie.setSecure(true);
        sessionCookie.setHttpOnly(true);
        return sessionCookie;
    }

    private Header errorHeader(String messageKey) {
        String localizedMessage = localize(messageKey);
        String localizedMessageBase64 = Base64.encode(localizedMessage).toString();
        return new Header(RESPONSE_ERROR_HEADER, localizedMessageBase64);
    }

    private String localize(String key) {
        return this.messageSource.getMessage(key, (Object[]) null, this.locale);
    }

    private ModelAndView generateLoginForm(String servicePrincipalName) {
        this.model.addAttribute("protocol",                     "openidconnect");
        this.model.addAttribute("responseMode",                 this.authnRequest.getResponseMode().toString());

        this.model.addAttribute("spn",                          StringEscapeUtils.escapeEcmaScript(servicePrincipalName));
        this.model.addAttribute("tenant_brandname",             StringEscapeUtils.escapeEcmaScript(this.tenantInfo.getBrandName()));
        this.model.addAttribute("tenant_logonbanner_title",     StringEscapeUtils.escapeEcmaScript(this.tenantInfo.getLogonBannerTitle()));
        this.model.addAttribute("tenant_logonbanner_content",   StringEscapeUtils.escapeEcmaScript(this.tenantInfo.getLogonBannerContent()));
        this.model.addAttribute("enable_logonbanner_checkbox",  this.tenantInfo.getLogonBannerEnableCheckbox());

        this.model.addAttribute("username",                     localize("LoginForm.UserName"));
        this.model.addAttribute("password",                     localize("LoginForm.Password"));
        this.model.addAttribute("passcode",                     localize("LoginForm.Passcode"));
        this.model.addAttribute("submit",                       localize("LoginForm.Submit"));
        this.model.addAttribute("error",                        localize("LoginForm.Error"));
        this.model.addAttribute("errorSSPI",                    localize("LoginForm.ErrorSSPI"));
        this.model.addAttribute("login",                        localize("LoginForm.Login"));
        this.model.addAttribute("help",                         localize("LoginForm.Help"));
        this.model.addAttribute("winSession",                   localize("LoginForm.WinSession"));
        this.model.addAttribute("downloadCIP",                  localize("LoginForm.DownloadCIP"));
        this.model.addAttribute("unsupportedBrowserWarning",    localize("LoginForm.UnsupportedBrowserWarning"));
        this.model.addAttribute("smartcard",                    localize("LoginForm.Smartcard"));
        this.model.addAttribute("iAgreeTo",                     localize("LoginForm.IAgreeTo"));
        this.model.addAttribute("logonBannerAlertMessage",      localize("LoginForm.LogonBannerAlertMessage"));
        this.model.addAttribute("rsaam",                        localize("LoginForm.RsaSecurID"));

        this.model.addAttribute("enable_password_auth",         this.tenantInfo.getAuthnPolicy().getAllowPasswordAuthn());
        this.model.addAttribute("enable_windows_auth",          this.tenantInfo.getAuthnPolicy().getAllowWindowsSessionAuthn());
        this.model.addAttribute("enable_tlsclient_auth",        false);
        this.model.addAttribute("enable_rsaam_auth",            false);

        return new ModelAndView("unpentry");
    }
}