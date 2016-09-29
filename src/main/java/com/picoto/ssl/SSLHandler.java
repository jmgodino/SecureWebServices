package com.picoto.ssl;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ResourceBundle;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.picoto.ciphers.AbstractCipher;

public class SSLHandler {

    protected static ResourceBundle bundle = ResourceBundle.getBundle("connection-security");

    private static final Logger LOG = LoggerFactory.getLogger(SSLHandler.class);

    protected SSLConfiguration conf;
    
    

    protected SSLHandler() {
        super();
    }

    public SSLHandler(SSLConfiguration conf) {
        super();
        this.conf = conf;
    }

    public SSLContext configure() {
        try {

            return configureSecureConnection(getTransportProtocol(),
                    conf.getKeyStoreConfiguration(), conf.getTrustStoreConfiguration());

        } catch (Exception e) {
            LOG.info("Excepcion configurando SSL", e);
            throw new SSLConfigurationException(
                    "Se ha producido un error al configurar la conexion SSL", e);
        }

    }

    protected SSLContext configureSecureConnection(String protocol,
            KeyStoreConfiguration keyStoreConf, KeyStoreConfiguration trustStoreConf)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            UnrecoverableKeyException, KeyManagementException {

        LOG.info("Asignando nueva factoria SSL");

        SSLContext sslCtx;
        // Almacen de claves privadas
        KeyStore ks = KeyStore.getInstance(keyStoreConf.getType());
        InputStream keyStoreIn = null;
        if (keyStoreConf.isFile()) {
            keyStoreIn = new FileInputStream(keyStoreConf.getFilePath());
        } else {
            keyStoreIn = SSLHandler.class.getResourceAsStream(keyStoreConf.getPath());
        }

        String passwd = AbstractCipher.getCipher().decrypt(keyStoreConf.getPassword());
        ks.load(keyStoreIn, passwd.toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());
        kmf.init(ks, passwd.toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        X509KeyManager km = new CustomX509KeyManager(keyStoreConf.getAlias(), kms);

        // Almacen de certificados de confianza
        KeyStore trustStore = KeyStore.getInstance(trustStoreConf.getType());
        InputStream certStoreIn = null;
        if (trustStoreConf.isFile()) {
            certStoreIn = new FileInputStream(trustStoreConf.getFilePath());
        } else {
            certStoreIn = SSLHandler.class.getResourceAsStream(trustStoreConf.getPath());
        }

        trustStore.load(certStoreIn,
                AbstractCipher.getCipher().decrypt(trustStoreConf.getPassword()).toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory
                .getDefaultAlgorithm());
        tmf.init(trustStore);
        TrustManager[] tms = tmf.getTrustManagers();

        // Iniciar contexto SSL
        sslCtx = SSLContext.getInstance(protocol);
        sslCtx.init(new X509KeyManager[] {km }, tms, new SecureRandom());

        return sslCtx;
    }

    public static int getSecurePort() {
        return Integer.parseInt(bundle.getString("secure.port"));
    }

    public static String getSecureProtocol() {
        return bundle.getString("secure.protocol");
    }
    
    public static String getTransportProtocol() {
        return bundle.getString("transport.protocol");
    }

}
