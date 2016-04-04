/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.symantecvip;

import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of SymantecVIP
 */
public class SymantecVIPAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(SymantecVIPAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside SymantecVIPAuthenticator canHandle method");
        }
        return (StringUtils.isNotEmpty(request.getParameter(SymantecVIPAuthenticatorConstants.SECURITY_CODE)));
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String p12file = authenticatorProperties.get(SymantecVIPAuthenticatorConstants.VIP_P12FILE);
            String p12password = authenticatorProperties.get(SymantecVIPAuthenticatorConstants.VIP_P12PASSWORD);
            if (StringUtils.isNotEmpty(p12file) && StringUtils.isNotEmpty(p12password)) {
                if (!context.isRetrying()) {
                    String tokenId = getFromClaim(context, SymantecVIPAuthenticatorConstants.VIP_CREDENTIAL_ID_CLAIM);
                    if (StringUtils.isEmpty(tokenId)) {
                        log.error("The Credential ID can not be null.");
                        throw new AuthenticationFailedException("The Credential ID can not be null.");
                    } else {
                        context.setProperty(SymantecVIPAuthenticatorConstants.TOKEN_ID, tokenId);
                    }
                }
                String retryParam = "";
                if (context.isRetrying()) {
                    retryParam = SymantecVIPAuthenticatorConstants.RETRY_PARAMS;
                }
                String vipPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                        .replace(SymantecVIPAuthenticatorConstants.LOGIN_PAGE, SymantecVIPAuthenticatorConstants.VIP_PAGE);
                String queryParams = FrameworkUtils
                        .getQueryStringWithFrameworkContextId(context.getQueryParams(),
                                context.getCallerSessionKey(),
                                context.getContextIdentifier());
                response.sendRedirect(response.encodeRedirectURL(vipPage + ("?" + queryParams))
                        + SymantecVIPAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                        + SymantecVIPAuthenticatorConstants.LOCAL
                        + retryParam);
            } else {
                log.error("Certificate path and password cannot be null");
                throw new AuthenticationFailedException("Certificate path and password cannot be null");
            }
        } catch (IOException e) {
            log.error("Exception while redirecting the page: " + e.getMessage(), e);
            throw new AuthenticationFailedException("Exception while redirecting the page: " + e.getMessage(), e);
        } catch (AuthenticationFailedException e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * Process the response of the Symantec VIP
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            if (StringUtils.isEmpty(request.getParameter(SymantecVIPAuthenticatorConstants.SECURITY_CODE))) {
                log.error("Security Code cannot not be null");
                throw new InvalidCredentialsException("Security Code cannot not be null");
            }
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String tokenId = context.getProperty(SymantecVIPAuthenticatorConstants.TOKEN_ID).toString();
            if (StringUtils.isEmpty(tokenId)) {
                log.error("The Credential ID can not be null.");
                throw new AuthenticationFailedException("The Credential ID can not be null.");
            } else {
                String p12file = authenticatorProperties.get(SymantecVIPAuthenticatorConstants.VIP_P12FILE);
                String p12password = authenticatorProperties.get(SymantecVIPAuthenticatorConstants.VIP_P12PASSWORD);
                String secretCode = request.getParameter(SymantecVIPAuthenticatorConstants.SECURITY_CODE);
                VIPManager.invokeSOAP(tokenId, secretCode, p12file, p12password);
                String username = context.getProperty(SymantecVIPAuthenticatorConstants.IS_USERNAME).toString();
                context.setSubject(AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(username.substring(0,
                                username.lastIndexOf("@"))));
            }
        } catch (AuthenticationFailedException e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage());
        }
    }

    private String getFromClaim(AuthenticationContext context, String claim) throws AuthenticationFailedException {
        String username = null;
        String tokenId = null;
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet()) {
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username =
                        String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                break;
            }
        }
        if (StringUtils.isNotEmpty(username)) {
            UserRealm userRealm = null;
            context.setProperty(SymantecVIPAuthenticatorConstants.IS_USERNAME, username);
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            try {
                userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new AuthenticationFailedException("Cannot find the user realm", e);
            }
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));

            if (userRealm != null) {
                try {
                    tokenId =
                            userRealm.getUserStoreManager().getUserClaimValue(username, claim, null).toString();
                } catch (UserStoreException e) {
                    throw new AuthenticationFailedException("Cannot find the user claim for VIP Credential ID " + e.getMessage(), e);
                }
                if (StringUtils.isEmpty(tokenId)) {
                    log.error("VIP Credentiad ID cannot be null.");
                    throw new AuthenticationFailedException("VIP Credentiad ID cannot be null.");
                }

            }
        }
        return tokenId;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return SymantecVIPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return SymantecVIPAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        Property p12file = new Property();
        p12file.setName(SymantecVIPAuthenticatorConstants.VIP_P12FILE);
        p12file.setDisplayName("P12FILE");
        p12file.setRequired(true);
        p12file.setDescription("Enter your p12_file path");
        p12file.setDisplayOrder(0);
        configProperties.add(p12file);

        Property p12password = new Property();
        p12password.setName(SymantecVIPAuthenticatorConstants.VIP_P12PASSWORD);
        p12password.setDisplayName("P12Password");
        p12password.setConfidential(true);
        p12password.setRequired(true);
        p12password.setDescription("Enter your p12_password");
        p12password.setDisplayOrder(1);
        configProperties.add(p12password);

        return configProperties;
    }
}

