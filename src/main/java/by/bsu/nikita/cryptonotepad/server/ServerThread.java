package by.bsu.nikita.cryptonotepad.server;

import by.bsu.nikita.cryptonotepad.logic.*;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;

public class ServerThread extends Thread {
    private static final int SESSION_KEY_LENGTH_BYTES = 16;
    private final ObjectOutputStream oos;
    private final ObjectInputStream ois;
    private final InetAddress address;

    public ServerThread(Socket socket) {
        try {
            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
            address = socket.getInetAddress();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public void run() {
        try {
            BigInteger publicKey = (BigInteger) ois.readObject();
            BigInteger N = ((BigInteger) ois.readObject());
            System.out.println("[S] Server got ePublicKey");
            System.out.println("[S] ePublicKey: " + publicKey);
            String sessionKey;

            sessionKey = generateSessionKey();
            System.out.println("[S] Session key generated: " + sessionKey);

            Encoder encoder = AesEncoder.getInstance();
            byte[] encSessionKey = RSA.encryptRSA(sessionKey.getBytes(), publicKey, N);
            oos.writeObject(encSessionKey);
//            System.out.println("[S] Session key encoded by ePublicKey: " + Hex.encodeHexString(encSessionKey));
            oos.flush();

            String login = encoder.decrypt((String) ois.readObject(), sessionKey);
            String password = encoder.decrypt(((String) ois.readObject()), sessionKey);

            boolean authenticate = AuthenticationManager.getInstance().authenticate(login, password);
            if (!authenticate) {
                oos.writeObject("Authenticate FAILED\n");
                oos.flush();
                oos.close();
                ois.close();
                return;
            }
            oos.writeObject("Authenticate SUCCESS\n");
            oos.flush();

            while (true) {
                String filename = encoder.decrypt(((String) ois.readObject()), sessionKey);
                System.out.println("Requested file: filename");
                String text = Reader.readFromFile(filename);
                if (text == null) {
                    text = "File Not Found!";
                }
                String encText = encoder.encrypt(text, sessionKey);
                oos.writeObject(encText);
                oos.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
            try {
                oos.close();
                ois.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }


    public static String generateSessionKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[SESSION_KEY_LENGTH_BYTES];

        random.nextBytes(key);
        return Hex.encodeHexString(key);
    }
}
