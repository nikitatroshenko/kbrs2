package by.bsu.nikita.cryptonotepad.logic;

import java.math.BigInteger;

/**
 * @author Nikita Atroshenko
 * @version 1.0
 */
public class RSA {

    // Encrypt message
    public static byte[] encryptRSA(byte[] message, BigInteger ePublicKey, BigInteger N)
    {
        return (new BigInteger(message)).modPow(ePublicKey, N).toByteArray();
    }

    // Decrypt message
    public static byte[] decryptRSA(byte[] message, BigInteger dPrivateKey, BigInteger N)
    {
        return (new BigInteger(message)).modPow(dPrivateKey, N).toByteArray();
    }
}
