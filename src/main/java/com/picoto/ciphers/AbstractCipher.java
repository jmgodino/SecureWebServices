package com.picoto.ciphers;

import java.util.ResourceBundle;

public abstract class AbstractCipher {

    private static ResourceBundle bundle = ResourceBundle.getBundle("connection-security");

    public abstract String encrypt(String texto);

    public abstract String decrypt(String texto);

    public static AbstractCipher getCipher() {
        String className = bundle.getString("cipher.impl");
        try {
            return (AbstractCipher) Class.forName(className).newInstance();
        } catch (Exception e) {
            return null;
        }
    }

}
