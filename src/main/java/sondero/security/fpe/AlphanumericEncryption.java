package sondero.security.fpe;

import java.math.BigInteger;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class AlphanumericEncryption {
    private static final int ROUNDS_TEN = 10;
    private static final int RADIX = 36;  // Base-36 for alphanumeric (0-9 and A-Z)

    // Encrypt method
    public BigInteger encrypt(byte[] aesKey, byte[] tweak, BigInteger input, int n, StringBuilder log) {
        int l = (n + 1) / 2;
        BigInteger bMagnitude = BigInteger.valueOf(RADIX).pow(l);  // base-36 magnitude for second half
        BigInteger aMagnitude = BigInteger.valueOf(RADIX).pow(n - l);  // base-36 magnitude for first half

        BigInteger[] split = input.divideAndRemainder(bMagnitude);
        BigInteger A = split[0];  // First half
        BigInteger B = split[1];  // Second half

        if (log != null) {
            log.append(String.format("Input (length = %d): \"%s\"\n", n, digits(input, n, RADIX)));
            if (tweak.length == 0) {
                log.append("No Tweak\n");
            } else {
                log.append(String.format("Tweak (length = %d): \"%s\"\n", tweak.length, new String(tweak)));
            }
            log.append("Intermediate values:\n");
        }

        // 10 Rounds of Feistel Network
        for (int i = 0; i < ROUNDS_TEN; i++) {
            BigInteger C = A.add(Fk(n, tweak, i, B, aesKey, log)).mod(aMagnitude);
            A = B;
            B = C;
        }

        BigInteger encrypted = A.multiply(bMagnitude).add(B);  // Combine the halves back together
        if (log != null) {
            log.append(String.format("Encrypted: \"%s\"\n", digits(encrypted, n, RADIX)));
        }

        return encrypted;
    }

    // Decrypt method
    public BigInteger decrypt(byte[] aesKey, byte[] tweak, BigInteger encrypted, int n, StringBuilder log) {
        int l = (n + 1) / 2;
        BigInteger bMagnitude = BigInteger.valueOf(RADIX).pow(l);
        BigInteger aMagnitude = BigInteger.valueOf(RADIX).pow(n - l);

        BigInteger[] split = encrypted.divideAndRemainder(bMagnitude);
        BigInteger A = split[0];  // First half
        BigInteger B = split[1];  // Second half

        if (log != null) {
            log.append(String.format("Encrypted Input (length = %d): \"%s\"\n", n, digits(encrypted, n, RADIX)));
            log.append("Intermediate values:\n");
        }

        // 10 Rounds of Feistel Network in reverse
        for (int i = ROUNDS_TEN - 1; i >= 0; i--) {
            BigInteger C = B.subtract(Fk(n, tweak, i, A, aesKey, log)).mod(aMagnitude);
            B = A;
            A = C;
        }

        BigInteger decrypted = A.multiply(bMagnitude).add(B);
        if (log != null) {
            log.append(String.format("Decrypted: \"%s\"\n", digits(decrypted, n, RADIX)));
        }

        return decrypted;
    }

    // Mocked Feistel function (Fk) for demonstration purposes
    private BigInteger Fk(int n, byte[] tweak, int round, BigInteger input, byte[] aesKey, StringBuilder log) {
        BigInteger result = input.add(BigInteger.valueOf(round));  // Dummy operation for Fk
        if (log != null) {
            log.append(String.format("Round %d, Fk = %s\n", round, digits(result, n, RADIX)));
        }
        return result;
    }

    // Helper method for padding and converting BigInteger to base-36 string
    private static String digits(BigInteger integer, int length, int radix) {
        String formatted = integer.toString(radix).toUpperCase();  // Base-36 and uppercase
        return String.format("%" + length + "s", formatted).replace(' ', '0');  // Zero-pad if necessary
    }

    public static void main(String[] args) {
        AlphanumericEncryption encryption = new AlphanumericEncryption();
        byte[] aesKey = new byte[16];  // Simulate AES key (16 bytes for AES-128)
        byte[] tweak = "TweakData".getBytes(StandardCharsets.UTF_8);  // Example tweak
        StringBuilder log = new StringBuilder();

        // Generate a random alphanumeric input to encrypt
        SecureRandom random = new SecureRandom();
        String input = "A1B2C3";
        BigInteger inputBigInt = new BigInteger(input, RADIX);  // Convert input to BigInteger (base-36)

        System.out.println("Original Input: " + input);

        // Encrypt the input
        BigInteger encrypted = encryption.encrypt(aesKey, tweak, inputBigInt, input.length(), log);
        String encryptedStr = encrypted.toString(RADIX).toUpperCase();  // Convert back to base-36 string

        System.out.println("Encrypted Output: " + encryptedStr);
        System.out.println(log.toString());  // Optional: View the encryption process in the log

        // Decrypt the encrypted value
        BigInteger decrypted = encryption.decrypt(aesKey, tweak, encrypted, input.length(), log);
        String decryptedStr = decrypted.toString(RADIX).toUpperCase();  // Convert back to base-36 string

        System.out.println("Decrypted Output: " + decryptedStr);

        if (input.equals(decryptedStr)) {
            System.out.println("Decryption successful! Original and decrypted values match.");
        } else {
            System.out.println("Decryption failed. Original and decrypted values do not match.");
        }
    }
}
