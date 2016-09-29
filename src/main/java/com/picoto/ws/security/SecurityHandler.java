package com.picoto.ws.security;

import java.io.IOException;
import java.util.HashSet;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.w3c.dom.Document;

import com.picoto.ciphers.AESCipher;

public class SecurityHandler implements SOAPHandler<SOAPMessageContext>, CallbackHandler {

    private Properties prop = new Properties();

    private boolean isEncrypt;

    private boolean isSignature;

    private boolean isTimestamp;

    private boolean isValidateResponse;

    protected SecurityHandler() {
        loadPropertiesFromBundle();
    }

    public SecurityHandler(boolean encrypt, boolean sign, boolean timestamp, boolean validate) {
        this();
        this.isEncrypt = encrypt;
        this.isSignature = sign;
        this.isTimestamp = timestamp;
        this.isValidateResponse = validate;
    }

    private void loadPropertiesFromBundle() {
        ResourceBundle bundle = ResourceBundle.getBundle("wssec");
        for (String clave : bundle.keySet()) {
            String valor = bundle.getString(clave);
            if (clave.indexOf("password") >= 0) {
                prop.put(clave, decode(valor));
            } else {
                prop.put(clave, valor);
            }    
        }
    }

    @Override
    public boolean handleMessage(SOAPMessageContext messageContext) {

        try {
            SOAPMessage msg = messageContext.getMessage();

            Boolean isOutGoing = (Boolean) messageContext
                    .get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

            if (isOutGoing) {
                if (isEncrypt) {
                    encryptSOAPEnvelope(msg, prop);
                }
                if (isTimestamp) {
                    timestampSOAPEnvelope(msg, prop);
                }
                if (isSignature) {
                    signSOAPEnvelope(msg, prop);
                }
            } else {
                if (isValidateResponse) {
                    checkSignatureAndDecode(msg, this, prop);
                }

            }

        } catch (Exception ex) {
            throw new SecurityHandlerException("Error tratando mensaje a securizar con WSS4J", ex);
        }

        return true;

    }

    @Override
    public boolean handleFault(SOAPMessageContext messageContext) {
        return true;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        String password;

        for (Callback cb : callbacks) {
            if (cb instanceof WSPasswordCallback) {

                WSPasswordCallback pc = (WSPasswordCallback) cb;

                try {
                    password = prop.getProperty("password");
                } catch (Exception e) {
                    throw new UnsupportedCallbackException(pc,
                            "Error recuperando propiedades de seguridad WSS4J");
                }

                if (pc.getIdentifier() != null) {
                    pc.setPassword(password);
                }

            }

        }

    }

    @Override
    public void close(MessageContext messageContext) {
    }

    @Override
    public Set<QName> getHeaders() {
        Set<QName> HEADERS = new HashSet<QName>();

        HEADERS.add(new QName(WSConstants.WSSE_NS, "Security"));
        HEADERS.add(new QName(WSConstants.WSSE11_NS, "Security"));
        HEADERS.add(new QName(WSConstants.ENC_NS, "EncryptedData"));

        return HEADERS;

    }

    private static SOAPMessage updateSOAPMessage(Document doc, SOAPMessage message)
            throws SOAPException {

        DOMSource domSource = new DOMSource(doc);
        message.getSOAPPart().setContent(domSource);

        return message;

    }

    public static Document toDocument(SOAPMessage soapMsg) throws SOAPException,
            TransformerException {

        Source src = soapMsg.getSOAPPart().getContent();

        TransformerFactory tf = TransformerFactory.newInstance();

        Transformer transformer = tf.newTransformer();

        DOMResult result = new DOMResult();
        transformer.transform(src, result);
        return (Document) result.getNode();

    }

    protected void checkSignatureAndDecode(SOAPMessage msg, CallbackHandler cb, Properties prop) {

        try {
            WSSecurityEngine secEngine = new WSSecurityEngine();
            Crypto crypto = CryptoFactory.getInstance(prop);
            Document doc = toDocument(msg);
            if (secEngine.processSecurityHeader(doc, null, cb, crypto) == null) {
                throw new SecurityHandlerException(
                        "No se ha validado la cabecera de seguridad de la respuesta");
            }
            updateSOAPMessage(doc, msg);
        } catch (Exception e) {
            throw new SecurityHandlerException("Error validando respuesta con WSS4J", e);
        }
    }

    protected void signSOAPEnvelope(SOAPMessage mensaje, Properties prop) {

        WSSecSignature signer = new WSSecSignature();

        try {
            String alias = prop.getProperty("security.handler.alias");
            String password = prop.getProperty("security.handler.password");
            signer.setUserInfo(alias, password);
            signer.setUseSingleCertificate(true);
            signer.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
            Crypto crypto = CryptoFactory.getInstance(prop);
            Document doc = toDocument(mensaje);
            WSSecHeader header = new WSSecHeader();
            header.setMustUnderstand(true);
            header.insertSecurityHeader(doc);
            Document signedDoc = signer.build(doc, crypto, header);
            DOMSource domSource = new DOMSource(signedDoc);
            mensaje.getSOAPPart().setContent(domSource);
        } catch (Exception e) {
            throw new SecurityHandlerException("Error firmando mensaje de salida con WSS4J", e);
        }

    }

    protected void timestampSOAPEnvelope(SOAPMessage mensaje, Properties prop) {
        try {
            WSSecTimestamp timestamp = new WSSecTimestamp();
            String ttl = prop.getProperty("security.handler.timestamp.ttl");
            timestamp.setTimeToLive(new Integer(ttl));
            Document doc = toDocument(mensaje);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.setMustUnderstand(true);
            secHeader.insertSecurityHeader(doc);
            Document timestampedDocument = timestamp.build(doc, secHeader);
            DOMSource domSource = new DOMSource(timestampedDocument);
            mensaje.getSOAPPart().setContent(domSource);
        } catch (Exception e) {
            throw new SecurityHandlerException(
                    "Error creando timestamp para mensaje de salida con WSS4J", e);
        }

    }

    protected void encryptSOAPEnvelope(SOAPMessage mensaje, Properties prop) {

        try {
            WSSecEncrypt encriptador = new WSSecEncrypt();
            String alias = prop.getProperty("security.handler.alias");
            String password = prop.getProperty("security.handler.password");
            encriptador.setUserInfo(alias, password);
            Crypto crypto = CryptoFactory.getInstance(prop);
            Document doc = toDocument(mensaje);
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.setMustUnderstand(true);
            secHeader.insertSecurityHeader(doc);
            Document signedDoc = encriptador.build(doc, crypto, secHeader);
            DOMSource domSource = new DOMSource(signedDoc);
            mensaje.getSOAPPart().setContent(domSource);
        } catch (Exception e) {
            throw new SecurityHandlerException("Error encriptando mensaje de salida con WSS4J", e);
        }
    }

    public String decode(String password) {
        try {
            String valor = new AESCipher().decrypt(password);
            return valor;
        } catch (Exception e) {
            throw new SecurityHandlerException("Error al desencriptar la password del fichero", e);
        }
    }


}
