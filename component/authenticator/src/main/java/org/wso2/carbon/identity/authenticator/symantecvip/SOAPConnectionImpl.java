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

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.OMText;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.OperationClient;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.engine.DispatchPhase;
import org.apache.axis2.engine.Phase;
import org.apache.axis2.saaj.MessageFactoryImpl;
import org.apache.axis2.saaj.util.IDGenerator;
import org.apache.axis2.saaj.util.SAAJUtil;
import org.apache.axis2.saaj.util.UnderstandAllHeadersHandler;

import javax.activation.DataHandler;
import javax.xml.namespace.QName;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.xml.soap.AttachmentPart;
import javax.xml.soap.MimeHeader;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;

public class SOAPConnectionImpl extends SOAPConnection {
    private boolean closed = false;
    private final ConfigurationContext configurationContext;

    SOAPConnectionImpl() throws SOAPException {
        try {
            this.configurationContext =
                    ConfigurationContextFactory.createConfigurationContextFromFileSystem((String) null, (String) null);
            this.disableMustUnderstandProcessing(this.configurationContext.getAxisConfiguration());
        } catch (AxisFault e) {
            throw new SOAPException(e);
        }
    }

    public SOAPMessage call(SOAPMessage request, Object endpoint) throws SOAPException {
        if (this.closed) {
            throw new SOAPException("SOAPConnection closed");
        } else {
            URL url;
            try {
                url = endpoint instanceof URL ? (URL) endpoint : new URL(endpoint.toString());
            } catch (MalformedURLException e) {
                throw new SOAPException(e.getMessage());
            }
            Options options = new Options();
            options.setTo(new EndpointReference(url.toString()));
            ServiceClient serviceClient;
            OperationClient opClient;
            try {
                serviceClient = new ServiceClient(this.configurationContext, (AxisService) null);
                opClient = serviceClient.createClient(ServiceClient.ANON_OUT_IN_OP);
            } catch (AxisFault e) {
                throw new SOAPException(e);
            }
            options.setProperty("CHARACTER_SET_ENCODING", request.getProperty("javax.xml.soap.character-set-encoding"));
            opClient.setOptions(options);
            MessageContext requestMsgCtx = new MessageContext();
            SOAPEnvelope envelope;
            Iterator responseMsgCtx;
            String attachments;
            envelope = SAAJUtil.toOMSOAPEnvelope(request.getSOAPPart().getDocumentElement());
            HashMap hashMap = null;
            responseMsgCtx = request.getMimeHeaders().getAllHeaders();
            while (responseMsgCtx.hasNext()) {
                MimeHeader mimeHeader = (MimeHeader) responseMsgCtx.next();
                attachments = mimeHeader.getName().toLowerCase();
                if (attachments.equals("soapaction")) {
                    requestMsgCtx.setSoapAction(mimeHeader.getValue());
                } else if (!attachments.equals("content-type")) {
                    if (hashMap == null) {
                        hashMap = new HashMap();
                    }
                    hashMap.put(mimeHeader.getName(), mimeHeader.getValue());
                }
            }
            if (hashMap != null) {
                requestMsgCtx.setProperty("HTTP_HEADERS", hashMap);
            }
            try {
                MessageContext messageContext;
                try {
                    requestMsgCtx.setEnvelope(envelope);
                    opClient.addMessageContext(requestMsgCtx);
                    opClient.execute(true);
                    messageContext = opClient.getMessageContext("In");
                } catch (AxisFault e) {
                    throw new SOAPException(e.getMessage(), e);
                }
                SOAPMessage soapMessage = this.getSOAPMessage(messageContext.getEnvelope());
                return soapMessage;
            } finally {
                try {
                    serviceClient.cleanupTransport();
                    serviceClient.cleanup();
                } catch (AxisFault e) {
                    throw new SOAPException(e);
                }
            }
        }
    }

    private void disableMustUnderstandProcessing(AxisConfiguration config) {
        DispatchPhase phase = getDispatchPhase(config.getInFlowPhases());
        if (phase != null) {
            phase.addHandler(new UnderstandAllHeadersHandler());
        }
        phase = getDispatchPhase(config.getInFaultFlowPhases());
        if (phase != null) {
            phase.addHandler(new UnderstandAllHeadersHandler());
        }
    }

    private static DispatchPhase getDispatchPhase(List<Phase> phases) {
        Iterator i$ = phases.iterator();
        Phase phase;
        do {
            if (!i$.hasNext()) {
                return null;
            }
            phase = (Phase) i$.next();
        } while (!(phase instanceof DispatchPhase));
        return (DispatchPhase) phase;
    }

    public void close() throws SOAPException {
        if (this.closed) {
            throw new SOAPException("SOAPConnection Closed");
        } else {
            try {
                this.configurationContext.terminate();
            } catch (AxisFault e) {
                throw new SOAPException(e.getMessage());
            }
            this.closed = true;
        }
    }

    private SOAPMessage getSOAPMessage(SOAPEnvelope respOMSoapEnv) throws SOAPException {
        SOAPMessage response = new MessageFactoryImpl().createMessage();
        SOAPPart sPart = response.getSOAPPart();
        javax.xml.soap.SOAPEnvelope env = sPart.getEnvelope();
        SOAPBody body = env.getBody();
        SOAPHeader header = env.getHeader();
        org.apache.axiom.soap.SOAPHeader header2 = respOMSoapEnv.getHeader();
        if (header2 != null) {
            Iterator hbIter = header2.examineAllHeaderBlocks();
            while (hbIter.hasNext()) {
                SOAPHeaderBlock hb = (SOAPHeaderBlock) hbIter.next();
                QName hbQName = hb.getQName();
                SOAPHeaderElement headerEle =
                        header.addHeaderElement(env.createName(hbQName.getLocalPart(), hbQName.getPrefix(),
                                hbQName.getNamespaceURI()));
                Iterator role = hb.getAllAttributes();
                while (role.hasNext()) {
                    OMAttribute attr = (OMAttribute) role.next();
                    QName attrQName = attr.getQName();
                    headerEle.addAttribute(env.createName(attrQName.getLocalPart(), attrQName.getPrefix(),
                            attrQName.getNamespaceURI()), attr.getAttributeValue());
                }
                String role1 = hb.getRole();
                if (role1 != null) {
                    headerEle.setActor(role1);
                }
                headerEle.setMustUnderstand(hb.getMustUnderstand());
                this.toSAAJElement(headerEle, hb, response);
            }
        }
        this.toSAAJElement(body, respOMSoapEnv.getBody(), response);
        return response;
    }

    private void toSAAJElement(SOAPElement saajEle, OMNode omNode, SOAPMessage saajSOAPMsg) throws SOAPException {
        if (!(omNode instanceof OMText)) {
            if (omNode instanceof OMElement) {
                OMElement omEle = (OMElement) omNode;
                OMNode omChildNode;
                SOAPElement saajChildEle;
                for (Iterator childIter = omEle.getChildren(); childIter.hasNext(); this.toSAAJElement(saajChildEle,
                        omChildNode, saajSOAPMsg)) {
                    omChildNode = (OMNode) childIter.next();
                    saajChildEle = null;
                    if (omChildNode instanceof OMText) {
                        OMText omChildEle1 = (OMText) omChildNode;
                        if (omChildEle1.isOptimized()) {
                            DataHandler omChildQName1 = (DataHandler) omChildEle1.getDataHandler();
                            AttachmentPart attribIter1 = saajSOAPMsg.createAttachmentPart(omChildQName1);
                            String attr1 = IDGenerator.generateID();
                            attribIter1.setContentId("<" + attr1 + ">");
                            attribIter1.setContentType(omChildQName1.getContentType());
                            saajSOAPMsg.addAttachmentPart(attribIter1);
                            SOAPElement attrQName1 = saajEle.addChildElement("Include", "xop",
                                    "http://www.w3.org/2004/08/xop/include");
                            attrQName1.addAttribute(saajSOAPMsg.getSOAPPart().getEnvelope().createName("href"), "cid:" +
                                    attr1);
                        } else {
                            saajChildEle = saajEle.addTextNode(omChildEle1.getText());
                        }
                    } else if (omChildNode instanceof OMElement) {
                        OMElement omChildEle = (OMElement) omChildNode;
                        QName omChildQName = omChildEle.getQName();
                        saajChildEle = saajEle.addChildElement(omChildQName.getLocalPart(), omChildQName.getPrefix(),
                                omChildQName.getNamespaceURI());
                        Iterator attribIter = omChildEle.getAllAttributes();
                        while (attribIter.hasNext()) {
                            OMAttribute attr = (OMAttribute) attribIter.next();
                            QName attrQName = attr.getQName();
                            saajChildEle.addAttribute(saajSOAPMsg.getSOAPPart().getEnvelope()
                                    .createName(attrQName.getLocalPart(), attrQName.getPrefix(),
                                            attrQName.getNamespaceURI()), attr.getAttributeValue());
                        }
                    }
                }
            }
        }
    }
}
