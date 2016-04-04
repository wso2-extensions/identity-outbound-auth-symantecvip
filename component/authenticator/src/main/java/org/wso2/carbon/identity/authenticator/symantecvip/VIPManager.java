/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.authenticator.symantecvip;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.axis2.saaj.MessageFactoryImpl;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import javax.xml.soap.SOAPConnection;
import javax.xml.soap.Name;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPPart;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.SecureRandom;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;

import java.util.Properties;

public class VIPManager {
    private static final Log log = LogFactory.getLog(VIPManager.class);

    /**
     * Set the client certificate to Default SSL Context
     */
    public static void setHttpsClientCert(String certificateFile, String certPassword) throws KeyStoreException,
            NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException,
            KeyManagementException, AuthenticationFailedException {
        if (certificateFile == null || !new File(certificateFile).exists()) {
            throw new AuthenticationFailedException("The certificate file is not found");
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        InputStream keyInput = new FileInputStream(certificateFile);
        keyStore.load(keyInput, certPassword.toCharArray());
        keyInput.close();
        keyManagerFactory.init(keyStore, certPassword.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        SSLContext.setDefault(context);
    }

    /**
     * Method to create SOAP connection
     */
    public static void invokeSOAP(String tokenId, String securityCode, String p12file, String p12password)
            throws AuthenticationFailedException {
        SOAPConnection soapConnection = null;
        try {
            setHttpsClientCert(p12file, p12password);
            Properties vipProperties = new Properties();
            String resourceName = SymantecVIPAuthenticatorConstants.PROPERTIES_FILE;
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            InputStream resourceStream = loader.getResourceAsStream(resourceName);
            try {
                vipProperties.load(resourceStream);
            } catch (IOException e) {
                throw new AuthenticationFailedException("Unable to load the properties file: " + e.getMessage(), e);
            }
            SOAPMessage soapMessage;
            soapConnection = new SOAPConnectionImpl();
            if (vipProperties.containsKey(SymantecVIPAuthenticatorConstants.VIP_URL)) {
                String url = vipProperties.getProperty(SymantecVIPAuthenticatorConstants.VIP_URL);
                soapMessage = validationSOAPMessage(vipProperties, tokenId, securityCode);
                if (soapMessage != null) {
                    String reasonCode;
                    SOAPMessage soapResponse = soapConnection.call(soapMessage, url);
                    if (soapResponse.getSOAPBody().getElementsByTagName("ValidateResponse").getLength() != 0) {
                        reasonCode =
                                soapResponse.getSOAPBody().getElementsByTagName("ReasonCode").item(0).getTextContent().toString();
                        if (StringUtils.isNotEmpty(reasonCode)
                                && !SymantecVIPAuthenticatorConstants.SUCCESS_CODE.equals(reasonCode)) {
                            String error = soapResponse.getSOAPBody().getElementsByTagName("StatusMessage").item(0)
                                    .getTextContent().toString();
                            throw new AuthenticationFailedException("Error occurred while validating the credentials:"
                                    + error);
                        }
                    } else {
                        throw new AuthenticationFailedException("Unable to find the provisioning ID");
                    }
                } else {
                    throw new AuthenticationFailedException("SOAP message cannot be null");
                }
            } else {
                throw new AuthenticationFailedException("VIP endpoint URL is not defined in properties file");
            }
        } catch (SOAPException e) {
            throw new AuthenticationFailedException("Error occurred while sending SOAP Request to Server: "
                    + e.getMessage(), e);
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException(e.getMessage());
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException
                | UnrecoverableKeyException | KeyManagementException e) {
            throw new AuthenticationFailedException("Error while adding certificate: " + e.getMessage(), e);
        } finally {
            try {
                if (soapConnection != null) {
                    soapConnection.close();
                }
            } catch (SOAPException e) {
                log.error("Error while closing the SOAP connection: " + e.getMessage(), e);
            }
        }
    }

    private static SOAPMessage validationSOAPMessage(Properties vipProperties, String tokenId, String securityCode)
            throws SOAPException, AuthenticationFailedException {
        SOAPMessage soapMessage = null;
        if (vipProperties.containsKey(SymantecVIPAuthenticatorConstants.SOAP_VIP_NS_URI)
                && vipProperties.containsKey(SymantecVIPAuthenticatorConstants.VERSION)) {
            soapMessage = new MessageFactoryImpl().createMessage();
            SOAPPart soapPart = soapMessage.getSOAPPart();
            String serverURI = vipProperties.getProperty(SymantecVIPAuthenticatorConstants.SOAP_VIP_NS_URI);
            SOAPEnvelope envelope = soapPart.getEnvelope();
            String namespacePrefix = SymantecVIPAuthenticatorConstants.SOAP_NAMESPACE_PREFIX;
            envelope.addNamespaceDeclaration(SymantecVIPAuthenticatorConstants.SOAP_ENVELOP_NAMESPACE_PREFIX,
                    SymantecVIPAuthenticatorConstants.SOAP_ENVELOP_HEADER);
            envelope.addNamespaceDeclaration(namespacePrefix, serverURI);
            SOAPBody soapBody = envelope.getBody();
            SOAPElement soapBodyElem =
                    soapBody.addChildElement(SymantecVIPAuthenticatorConstants.SOAP_ACTION_VALIDATE, namespacePrefix);
            Name attributeName = envelope.createName(SymantecVIPAuthenticatorConstants.VERSION);
            soapBodyElem.addAttribute(attributeName, vipProperties.getProperty(SymantecVIPAuthenticatorConstants.VERSION));
            SOAPElement soapBodyElem1 =
                    soapBodyElem.addChildElement(SymantecVIPAuthenticatorConstants.TOKEN_ID, namespacePrefix);
            soapBodyElem1.addTextNode(tokenId);
            SOAPElement soapBodyElem2 =
                    soapBodyElem.addChildElement(SymantecVIPAuthenticatorConstants.OTP, namespacePrefix);
            soapBodyElem2.addTextNode(securityCode);
            MimeHeaders headers = soapMessage.getMimeHeaders();
            headers.addHeader(SymantecVIPAuthenticatorConstants.SOAP_ACTION, serverURI);
            soapMessage.saveChanges();
        } else {
            throw new AuthenticationFailedException("Some of the mandatory properties are not defined in properties file");
        }
        return soapMessage;
    }
}
