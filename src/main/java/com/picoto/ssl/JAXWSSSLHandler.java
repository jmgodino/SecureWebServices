package com.picoto.ssl;

import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JAXWSSSLHandler extends SSLHandler implements SOAPHandler<SOAPMessageContext> {

    private static final Logger LOG = LoggerFactory.getLogger(JAXWSSSLHandler.class);

    public JAXWSSSLHandler() {
        super();
        conf = new SSLConfiguration(new KeyStoreConfiguration(bundle.getString("senado.ssl.ks"),
                bundle.getString("senado.ssl.ks.pass"),
                bundle.getString("senado.ssl.store.type"),
                bundle.getString("senado.ssl.ks.alias")), new KeyStoreConfiguration(
                bundle.getString("senado.ssl.ts"), bundle.getString("senado.ssl.ts.pass"),
                bundle.getString("senado.ssl.store.type")));
    }

    @Override
    public void close(MessageContext ctx) {
    }

    @Override
    public boolean handleFault(SOAPMessageContext ctx) {
        return false;
    }

    @Override
    public boolean handleMessage(SOAPMessageContext ctx) {
        configure(ctx);
        return true;
    }

    @Override
    public Set<QName> getHeaders() {
        return null;
    }

    protected void configure(SOAPMessageContext context) {
        try {

            SSLContext sslCtx = configureSecureConnection(getTransportProtocol(),
                    conf.getKeyStoreConfiguration(), conf.getTrustStoreConfiguration());

            context.put("com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory", sslCtx.getSocketFactory());
        } catch (Exception e) {
            LOG.info("Excepcion configurando SSL", e);
            throw new SSLConfigurationException(
                    "Se ha producido un error al configurar la conexion SSL", e);
        }

    }
}
