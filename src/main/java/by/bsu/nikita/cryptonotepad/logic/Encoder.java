package by.bsu.nikita.cryptonotepad.logic;

public interface Encoder {
    String encrypt(String plainText, String key) throws Exception;

    String decrypt(String encryptedIvText, String key) throws Exception;
}
