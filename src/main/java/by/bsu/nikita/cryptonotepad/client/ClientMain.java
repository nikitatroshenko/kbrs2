package by.bsu.nikita.cryptonotepad.client;

import by.bsu.nikita.cryptonotepad.logic.AesEncoder;
import by.bsu.nikita.cryptonotepad.logic.RSA;
import by.bsu.nikita.cryptonotepad.logic.Encoder;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ClientMain {
    private static final int BIT_LENGTH = 1024;
    private static final long PIN_TIMEOUT = 1000 * 60; // one minute
    private static BigInteger N;
    private static BigInteger publicKey;
    private static BigInteger privateKey;
    private static Properties properties;
    private static Date lastActivity;
    private static int failedAttempts;

    public static void main(String[] args) {
        try {
            String serverHost = System.getProperty("cryptonotepad.host", "localhost");
            int serverPort = Integer.parseInt(System.getProperty("cryptonotepad.port", "8888"));
            Socket socket = new Socket(serverHost, serverPort);

            ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream is = new ObjectInputStream(socket.getInputStream());

            generateRsaPairKey();
//            System.out.println("[C] RSA key pair generated.");
//            System.out.println("[C] ePublicKey: " + publicKey);
            os.writeObject(publicKey);
            os.writeObject(N);
            os.flush();

            byte[] encSessionKey;
            encSessionKey = (byte[]) is.readObject();
            String decSessionKey = new String(RSA.decryptRSA(encSessionKey, privateKey, N));

//            System.out.println("[C] Client decoded session key by dPrivateKey");
//            System.out.println("[C] decSessionKey: " + decSessionKey);

            Pair<String, String> credentials = getCredentials();
            Encoder encoder = AesEncoder.getInstance();
            os.writeObject(encoder.encrypt(credentials.getLeft(), decSessionKey));
            os.writeObject(encoder.encrypt(credentials.getRight(), decSessionKey));
            credentials.setValue(null);
            os.flush();

            String response = (String) is.readObject();
            if (!response.matches(".*SUCCESS\\n?.*")) {
                System.out.println(response);
                is.close();
                os.close();
                return;
            }

            Integer pin = getStoredPin();
            if (pin == null) {
                System.out.println("Creating new pin");
                pin = getPinFromTerminal();
            }
            savePin(pin);
            lastActivity = new Date();

            while (true) {
                Scanner in = new Scanner(System.in);

                System.out.println("Enter filename:");
                String filename = in.nextLine();

                Date now = new Date();
                if (now.getTime() - lastActivity.getTime() > PIN_TIMEOUT) {
                    System.out.println("You were idle for " + PIN_TIMEOUT / 1000 / 60 + " minutes. Enter your PIN");
                    checkPinStateful();
                    failedAttempts = 0;
                    System.out.println("Pin correct");
                }
                lastActivity = now;

                if (":newpin".equals(filename)) {
                    System.out.println("Changing your PIN. Enter your existing PIN:");
                    checkPinStateful();
                    System.out.println("Enter new PIN:");
                    int newPin = getPinFromTerminal();
                    savePin(newPin);
                    continue;
                }

                os.writeObject(encoder.encrypt(filename, decSessionKey));

                String encText = (String) is.readObject();

//                System.out.println("[C] Client got text, encoded session key:\n" + new String(Hex.decodeHex(encText)));
//                System.out.println("[C] encSessionKey: " + Hex.encodeHexString(encSessionKey));

                String decText = encoder.decrypt(encText, decSessionKey);
//                System.out.println("[C] Client decoded text");
//                System.out.println("[C] decText:\n\n" + decText);
                System.out.println(decText);
            }
        } catch (Exception ex) {
            Logger.getLogger(ClientMain.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void checkPinStateful() throws Exception {
        while (!checkPin()) {
            failedAttempts++;
            System.out.println("Wrong pin");
            if (failedAttempts == 3) {
                System.out.println("3 wrong pins. Exiting...");
                System.exit(0);
            }
        }
    }

    private static boolean checkPin() {
        int stored = Integer.parseInt(properties.getProperty("pin"));
        int entered = getPinFromTerminal();

        return stored == entered;
    }

    private static void savePin(Integer pin) {
        properties.setProperty("pin", String.valueOf(pin));

        File file = new File("pinstorage.properties");
        try {
            if (!file.exists()) {
                file.createNewFile();
            }
            properties.store(new FileOutputStream(file), null);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static int getPinFromTerminal() {
        Scanner in = new Scanner(System.in);

        while (true) {
            System.out.println("Enter 4 digit pin: ");
            String pinStr = in.nextLine();

            if (!pinStr.matches("\\d{4}")) {
                continue;
            }

            return Integer.valueOf(pinStr);
        }
    }

    private static Integer getStoredPin() {
        System.getProperty("java.class.path"); // XXX

        if (properties == null) {
            properties = new Properties();
            try {
                InputStream resourceAsStream = ClientMain.class.getClassLoader().getResourceAsStream("pinstorage.properties");
                if (resourceAsStream == null) {
                    File newFile = new File("pinstorage.properties");

                    newFile.createNewFile();
                    resourceAsStream = new FileInputStream(newFile);
                }
                properties.load(resourceAsStream);
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
        String pin = properties.getProperty("pin", null);
        return StringUtils.isNotEmpty(pin) ? Integer.valueOf(pin) : null;
    }

    private static Pair<String, String> getCredentials() {
        Scanner in = new Scanner(System.in);

        System.out.println("Login: ");
        String login = in.nextLine();
        System.out.println("Password: ");
        String password = in.nextLine();

        return new MutablePair<>(login, password);
    }

    private static void generateRsaPairKey() {
        Random r = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH, r);
        BigInteger q = BigInteger.probablePrime(BIT_LENGTH, r);
        N = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        publicKey = BigInteger.probablePrime(BIT_LENGTH / 2, r);
        while (phi.gcd(publicKey).compareTo(BigInteger.ONE) > 0 && publicKey.compareTo(phi) < 0) {
            publicKey = publicKey.add(BigInteger.ONE);
        }
        privateKey = publicKey.modInverse(phi);
    }
}
