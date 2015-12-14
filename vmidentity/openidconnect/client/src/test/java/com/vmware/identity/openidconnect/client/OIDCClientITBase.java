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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import org.junit.AfterClass;

import com.vmware.identity.rest.core.data.CertificateDTO;
import com.vmware.identity.rest.idm.client.IdmClient;
import com.vmware.identity.rest.idm.data.OIDCClientDTO;
import com.vmware.identity.rest.idm.data.OIDCClientMetadataDTO;
import com.vmware.identity.rest.idm.data.SolutionUserDTO;
import com.vmware.identity.rest.idm.data.attributes.MemberType;

/**
 * Base Class for OIDC Client Integration Test
 *
 * @author Jun Sun
 */
public class OIDCClientITBase {

    static ClientID clientId;
    static AccessToken accessToken;
    static OIDCClient nonRegNoHOKConfigClient, nonRegHOKConfigClient, regClient, regClientWithHA;
    static TokenSpec bearerWithRefreshSpec, bearerWithoutRefreshSpec, hokWithRefreshSpec, hokWithoutRefreshSpec;
    static PasswordCredentialsGrant passwordCredentialsGrant;
    static SolutionUserCredentialsGrant solutionUserCredentialsGrant;
    static ClientCredentialsGrant clientCredentialsGrant;

    static IdmClient idmClient;
    static String tenant;
    static String solutionUserName;

    public static void setUp(String config) throws Exception {
        Properties properties = new Properties();
        properties.load(OIDCClientIT.class.getClassLoader().getResourceAsStream(config));
        String username = properties.getProperty("admin.user");
        String password = properties.getProperty("admin.password");
        tenant = properties.getProperty("tenant");
        String domainControllerFQDN = properties.getProperty("oidc.op.FQDN");
        int domainControllerPort = Integer.parseInt(properties.getProperty("oidc.op.port"));

        // create admin client with STS token
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);

        // create REST afd client to populate SSL certificates
        TestUtils.populateSSLCertificates(
                domainControllerFQDN,
                domainControllerPort,
                ks);

        // retrieve OIDC meta data
        MetadataHelper metadataHelper = new MetadataHelper.Builder(domainControllerFQDN)
        .domainControllerPort(domainControllerPort)
        .tenant(tenant)
        .keyStore(ks).build();

        ProviderMetadata providerMetadata = metadataHelper.getProviderMetadata();
        RSAPublicKey providerPublicKey = metadataHelper.getProviderRSAPublicKey(providerMetadata);

        // create a non-registered OIDC client and get bearer tokens by admin user name/password
        ConnectionConfig connectionConfig = new ConnectionConfig(providerMetadata, providerPublicKey, ks);
        ClientConfig clientConfig = new ClientConfig(connectionConfig, null, null);
        nonRegNoHOKConfigClient = new OIDCClient(clientConfig);
        passwordCredentialsGrant = new PasswordCredentialsGrant(
                username,
                password);
        TokenSpec tokenSpec = new TokenSpec.Builder().resouceServers(Arrays.asList("rs_admin_server")).build();
        OIDCTokens oidcTokens = nonRegNoHOKConfigClient.acquireTokens(passwordCredentialsGrant, tokenSpec);
        accessToken = oidcTokens.getAccessToken();

        // create REST idm client
        idmClient = TestUtils.createIdmClient(
                accessToken,
                domainControllerFQDN,
                domainControllerPort,
                ks);

        // create key pair and client private key, certificate
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024, new SecureRandom());
        KeyPair clientKeyPair = keyGen.generateKeyPair();
        RSAPrivateKey clientPrivateKey = (RSAPrivateKey) clientKeyPair.getPrivate();
        solutionUserName = properties.getProperty("oidc.rp.prefix") + UUID.randomUUID().toString();
        X509Certificate clientCertificate = TestUtils.generateCertificate(clientKeyPair, solutionUserName);

        // create a solution user
        CertificateDTO certificateDTO = new CertificateDTO.Builder()
        .withEncoded(TestUtils.convertToBase64PEMString(clientCertificate))
        .build();
        SolutionUserDTO solutionUserDTO = new SolutionUserDTO.Builder()
        .withName(solutionUserName)
        .withDomain(tenant)
        .withCertificate(certificateDTO)
        .build();
        idmClient.solutionUser().create(tenant, solutionUserDTO);

        // add the solution user to ActAs group
        List<String> members = Arrays.asList(solutionUserName + "@" + tenant);
        idmClient.group().addMembers(tenant, "ActAsUsers", tenant, members, MemberType.USER);

        // register a OIDC client
        List<String> redirectURIs = Arrays.asList("https://test.com:7444/openidconnect/redirect");
        List<String> postLogoutRedirectURIs = Arrays.asList("https://test.com:7444/openidconnect/postlogout");
        String logoutURI = "https://test.com:7444/openidconnect/logout";
        OIDCClientMetadataDTO oidcClientMetadataDTO = new OIDCClientMetadataDTO.Builder()
        .withRedirectUris(redirectURIs)
        .withPostLogoutRedirectUris(postLogoutRedirectURIs)
        .withLogoutUri(logoutURI)
        .withTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
        .withCertSubjectDN(clientCertificate.getSubjectDN().getName())
        .build();
        OIDCClientDTO oidcClientDTO = idmClient.oidcClient().register(tenant, oidcClientMetadataDTO);
        clientId = new ClientID(oidcClientDTO.getClientId());

        // create client config
        connectionConfig = new ConnectionConfig(providerMetadata, providerPublicKey, ks);
        HolderOfKeyConfig holderOfKeyConfig = new HolderOfKeyConfig(clientPrivateKey, clientCertificate);

        // create clients
        clientConfig = new ClientConfig(connectionConfig, null, null);
        nonRegNoHOKConfigClient = new OIDCClient(clientConfig);
        clientConfig = new ClientConfig(connectionConfig, null, holderOfKeyConfig);
        nonRegHOKConfigClient = new OIDCClient(clientConfig);
        clientConfig = new ClientConfig(connectionConfig, clientId, holderOfKeyConfig);
        regClient = new OIDCClient(clientConfig);

        // create registered HA client
        String domainName = null;
        String availableDomainController = connectionConfig.getIssuer().getURI().getHost();
        ClientDCCacheFactory factory = new MockClientDCCacheFactory(domainName, availableDomainController);
        HighAvailabilityConfig haConfig = new HighAvailabilityConfig(domainName, factory);
        clientConfig = new ClientConfig(connectionConfig, clientId, holderOfKeyConfig, haConfig);
        regClientWithHA = new OIDCClient(clientConfig);

        // create token specs
        // TODO: there is no more difference between bearer and hok tokenSpec so we should delete the duplicates
        bearerWithRefreshSpec = new TokenSpec.Builder().
                refreshToken(true).
                idTokenGroups(GroupMembershipType.FULL).
                accessTokenGroups(GroupMembershipType.FULL).
                resouceServers(Arrays.asList("rs_admin_server")).build();
        bearerWithoutRefreshSpec = new TokenSpec.Builder().
                idTokenGroups(GroupMembershipType.FULL).
                accessTokenGroups(GroupMembershipType.FULL).
                resouceServers(Arrays.asList("rs_admin_server")).build();
        hokWithRefreshSpec = new TokenSpec.Builder().
                refreshToken(true).
                idTokenGroups(GroupMembershipType.FULL).
                accessTokenGroups(GroupMembershipType.FULL).
                resouceServers(Arrays.asList("rs_admin_server")).build();
        hokWithoutRefreshSpec = new TokenSpec.Builder().
                idTokenGroups(GroupMembershipType.FULL).
                accessTokenGroups(GroupMembershipType.FULL).
                resouceServers(Arrays.asList("rs_admin_server")).build();

        // create grants
        passwordCredentialsGrant = new PasswordCredentialsGrant(username, password);
        solutionUserCredentialsGrant = new SolutionUserCredentialsGrant();
        clientCredentialsGrant = new ClientCredentialsGrant();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        // delete solution user
        idmClient.user().delete(tenant, solutionUserName, tenant);

        // delete OIDC client here.
        idmClient.oidcClient().delete(tenant, clientId.getValue());
    }
}
