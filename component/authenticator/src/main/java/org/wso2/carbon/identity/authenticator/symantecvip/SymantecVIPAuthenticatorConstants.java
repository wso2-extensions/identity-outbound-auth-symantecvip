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

public class SymantecVIPAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "SymantecVIP";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "SymantecVIPAuthenticator";

    public static final String LOGIN_PAGE = "authenticationendpoint/login.do";
    public static final String VIP_PAGE = "symantecvipauthenticationendpoint/symantecvip.jsp";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String LOCAL = "LOCAL";

    public static final String PROPERTIES_FILE = "symantecvip.properties";
    public static final String VIP_URL = "vipURL";
    public static final String VIP_P12FILE = "P12file";
    public static final String VIP_P12PASSWORD = "P12KeystorePassword";
    public static final String VIP_CREDENTIAL_ID_CLAIM = "http://wso2.org/claims/vipcredentialid";

    public static final String IS_USERNAME = "Username";
    public static final String SECURITY_CODE = "SecurityCode";
    public static final String TOKEN_ID = "TokenId";
    public static final String OTP = "OTP";
    public static final String SUCCESS_CODE = "0000";
    public static final String VERSION= "Version";

    public static final String SOAP_ACTION = "SOAPAction";
    public static final String SOAP_ENVELOP_NAMESPACE_PREFIX = "soapenv";
    public static final String SOAP_ENVELOP_HEADER = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String SOAP_NAMESPACE_PREFIX = "vip";
    public static final String SOAP_VIP_NS_URI = "vipURI";
    public static final String SOAP_ACTION_VALIDATE = "Validate";
}