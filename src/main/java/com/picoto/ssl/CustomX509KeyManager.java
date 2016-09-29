package com.picoto.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class CustomX509KeyManager implements X509KeyManager {

    private static final Logger LOG = LoggerFactory.getLogger(CustomX509KeyManager.class);
    
    X509KeyManager km;
    
    private String alias;

    public CustomX509KeyManager(String alias, KeyManager[] kms) {
        this.alias = alias;
        for (KeyManager current : kms) {
            if (current instanceof X509KeyManager) {
                LOG.debug("Encontrado keymanager para alias: "+alias);
                km = (X509KeyManager) current;
            }
        }
        if (km == null) {
            throw new SSLConfigurationException("No se ha encontrado un KeyManager disponible para la conexion SSL");
        }
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return km.getCertificateChain(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return km.getClientAliases(keyType, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return km.getPrivateKey(alias);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }

}

