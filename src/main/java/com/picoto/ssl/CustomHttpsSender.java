package com.picoto.ssl;

import java.util.ResourceBundle;


import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.java.security.SSLProtocolSocketFactory;
import org.apache.axis2.transport.http.CommonsHTTPTransportSender;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomHttpsSender  extends CommonsHTTPTransportSender {

   
    private static final Logger LOG = LoggerFactory.getLogger(CustomHttpsSender.class);

    protected ResourceBundle settings;

    public CustomHttpsSender() {
        super();
        settings = ResourceBundle.getBundle("connection-security");
    }

    
    public CustomHttpsSender(ResourceBundle settings) {
        super();
        this.settings = settings;
    }
    
    
    public ResourceBundle getSettings() {
        return settings;
    }


    public void setSettings(ResourceBundle settings) {
        this.settings = settings;
    }



    @Override
    public InvocationResponse invoke(MessageContext ctx) throws AxisFault {
        LOG.info("Configurando la conexion SSL en handler propio del Senado");
        SSLConfiguration conf = new SSLConfiguration(new KeyStoreConfiguration(
                settings.getString("senado.ssl.ks"), settings.getString("senado.ssl.ks.pass"),
                settings.getString("senado.ssl.store.type"), settings.getString("senado.ssl.ks.alias")),
                new KeyStoreConfiguration(settings.getString("senado.ssl.ts"), settings
                        .getString("senado.ssl.ts.pass"), settings.getString("senado.ssl.store.type")));

        ctx.getOptions().setProperty(
                HTTPConstants.CUSTOM_PROTOCOL_HANDLER,
                new Protocol(SSLHandler.getSecureProtocol(),
                        (ProtocolSocketFactory) new SSLProtocolSocketFactory(new SSLHandler(conf)
                                .configure()), SSLHandler.getSecurePort()));
        
        return super.invoke(ctx);
    }


}
