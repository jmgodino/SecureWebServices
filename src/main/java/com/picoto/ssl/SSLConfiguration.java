package com.picoto.ssl;

public class SSLConfiguration {
    
    private KeyStoreConfiguration keyStoreConfiguration;
    
    private KeyStoreConfiguration trustStoreConfiguration;

    public SSLConfiguration(KeyStoreConfiguration keyStoreConfiguration,
            KeyStoreConfiguration trustStoreConfiguration) {
        super();
        this.keyStoreConfiguration = keyStoreConfiguration;
        this.trustStoreConfiguration = trustStoreConfiguration;
    }

    public KeyStoreConfiguration getKeyStoreConfiguration() {
        return keyStoreConfiguration;
    }

    public void setKeyStoreConfiguration(KeyStoreConfiguration keyStoreConfiguration) {
        this.keyStoreConfiguration = keyStoreConfiguration;
    }

    public KeyStoreConfiguration getTrustStoreConfiguration() {
        return trustStoreConfiguration;
    }

    public void setTrustStoreConfiguration(KeyStoreConfiguration trustStoreConfiguration) {
        this.trustStoreConfiguration = trustStoreConfiguration;
    }
    
    

}
