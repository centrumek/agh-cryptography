package potaczala.pawel.pl.edu.agh.cryptography.symmetric_cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.security.spec.KeySpec;

class CipherBox {
    private static final String PASSWORD = "ala123";
    private static final String SALT = "slonemorze";
    private static final byte[] iv = {17, 132 - 32, 54, 98, 223 - 128, 7, 42, 113, 135 - 32, 201 - 128, 59, 69, 11, 35, 148 - 21, 12};
    private static final IvParameterSpec ivspec = new IvParameterSpec(iv); //wektor inicjalizacyjny

    CipherBox() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private SecretKey secretKey;
    private Cipher cipher;

    Cipher initCipher() {

        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(PASSWORD.toCharArray(), SALT.getBytes(), 65536, 128);
            SecretKey tmp = secretKeyFactory.generateSecret(keySpec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            return cipher;

        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Error in cipher initialization");
        }
        return null;
    }

    void startEncryption() {
        try {
            cipher.init(Cipher.ENCRYPT_MODE , secretKey, ivspec);

        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Encryption cannot be started");
        }

    }

    void startDecryption() {
        try {
            cipher.init(Cipher.DECRYPT_MODE , secretKey, ivspec);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Decryption cannot be started");
        }

    }

    byte[] encryptBlock(byte[] message, boolean last, int dataSize) {
        try {
            return cryptBlock(message, last, dataSize);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Error in encryption");
        }
        return null;
    }

    byte[] decryptBlock(byte[] message, boolean last, int dataSize) {
        try {
            return cryptBlock(message, last, dataSize);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Error in decryption");
        }
        return null;
    }

    private byte[] cryptBlock(byte[] message, boolean last, int dataSize) throws Exception {
        if(last) return cipher.doFinal(message, 0, dataSize);
        else return cipher.update(message, 0, dataSize);
    }
}
