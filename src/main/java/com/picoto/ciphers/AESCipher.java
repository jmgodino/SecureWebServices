package com.picoto.ciphers;

import java.io.UnsupportedEncodingException;
import java.util.ResourceBundle;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AESCipher extends AbstractCipher {


    private static final ResourceBundle bundle = ResourceBundle.getBundle("connection-security");

    public AESCipher() {

    }

    protected String encrypt(String secretKey, String plainText) throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, secretKey);
        return new String(new Base64().encode(cipher.doFinal(plainText.getBytes(bundle.getString("message.encoding")))));
    }

    protected String decrypt(String secretKey, String encryptedText) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(Base64.decodeBase64(encryptedText.getBytes())), bundle.getString("message.encoding"));
    }

    protected Cipher getCipher(int mode, String secretKey) {

        try {
           
            SecretKey mySecretKey = new SecretKeySpec(secretKey.getBytes(bundle.getString("message.encoding")), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(mode, mySecretKey);
            
            return cipher;
        } catch (Exception e) {
            throw new CipherException("Error al inicializar el cifrado", e);
        }
    }

    @Override
    public String encrypt(String texto) {
        try {
            return encrypt(bundle.getString("secret.key"), texto);
        } catch (Exception e) {
            throw new CipherException("Error al encriptar la clave", e);
        }
    }

    @Override
    public String decrypt(String texto) {
        try {
            return decrypt(bundle.getString("secret.key"), texto);
        } catch (Exception e) {
            throw new CipherException("Error al encriptar la clave", e);
        }
    }

}
