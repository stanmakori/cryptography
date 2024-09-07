package sondero.security.fpe;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
public class Main {
    // Custom shorthand for System.out.println
    public static void sout(String message) {
        System.out.println(message);
    }
    public static void main(String[] args) {
        sout("====Numeric Encryption========");
        // Convert hex string to byte array
        // This is juts a string and not an atual AES key, jipange on production
        byte[] aesKey = hexToBytes("rM*66T-L+>*$&!^<yY^=igHP^<vl]!1x");
        byte[] T = {};  // Empty byte array for T
        BigInteger X = BigInteger.valueOf(722004444);  // Can be  without zero
        int n = 10;  // Value of n

        BigInteger expResult = BigInteger.valueOf(722004444);  // Expected result

        FPEUtility instance = new FPEUtility();  // Instance of FPEUtility class
        StringBuilder log = new StringBuilder();  // Log for storing output

        // Encrypt
        BigInteger result = instance.encrypt(aesKey, T, X, n, log);
        sout("Encrypted string is: " + result);

        // Decrypt
        BigInteger decryptedNum = instance.decrypt(aesKey, T, result, n, log);
        sout("Decrypted string is: " + decryptedNum);
        sout("====Alphanumeric Encryption========");


    }
    // Utility method to convert hex string to byte array
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}