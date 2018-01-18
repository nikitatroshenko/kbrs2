package by.bsu.nikita.cryptonotepad.server;

import by.bsu.nikita.cryptonotepad.logic.AuthenticationManager;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerMain {

    public static void main(String[] args) {
        try (ServerSocket server = new ServerSocket(8888)) {
            System.out.println("Initializing credentials storage");
            initCredentialsStorage();
            System.out.println("Server is initialized successfully.");
            while (true) {
                System.out.println("Listening...");
                Socket socket = server.accept();
                System.out.println(socket.getInetAddress().getHostName() + " connected");
                ServerThread connectionThread = new ServerThread(socket);
                connectionThread.start();
            }
        } catch (Exception ex) {
            Logger.getLogger(ServerMain.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void initCredentialsStorage() throws IOException {
        Properties properties = new Properties();

        properties.load(ServerMain.class.getResourceAsStream("/credentials.properties"));
        AuthenticationManager.getInstance().setProperties(properties);
        System.out.println("properties = " + properties);
    }
}
