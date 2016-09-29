package com.picoto.ws.logging;

import java.io.ByteArrayOutputStream;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogHandler implements SOAPHandler<SOAPMessageContext> {

    private static final Logger LOG = LoggerFactory.getLogger(LogHandler.class);

    public Set<QName> getHeaders() {
        return null;
    }

    public boolean handleMessage(SOAPMessageContext smc) {
        log(smc);
        return true;
    }

    public boolean handleFault(SOAPMessageContext smc) {
        log(smc);
        return true;
    }

    public void close(MessageContext messageContext) {
    }

    private void log(SOAPMessageContext smc) {
        Boolean outboundProperty = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

        if (outboundProperty.booleanValue()) {
            LOG.info("Mensaje de salida:");
        } else {
            LOG.info("Mensaje de entrada:");
        }

        SOAPMessage message = smc.getMessage();
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            message.writeTo(bos);
            LOG.info(bos.toString());
        } catch (Exception e) {
            LOG.info("Excepcion imprimiendo mensaje SOAP: " + e);
        }
    }
}
