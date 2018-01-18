package by.bsu.nikita.cryptonotepad.logic;

import java.util.Map;
import java.util.Objects;
import java.util.Properties;

public class AuthenticationManager {

    private static AuthenticationManager instance = new AuthenticationManager();
    private Properties properties;

    public boolean authenticate(String login, String password) {
        String credentialsKey = getCredentialsKey(login);

        String storedPassword = properties.getProperty(credentialsKey, null);

        return Objects.equals(password, storedPassword);
    }

    private String getCredentialsKey(String login) {
        return String.format("%s.password", login);
    }

    public void setProperties(Map properties) {
        if (this.properties == null) {
            this.properties = new Properties();
        }
        this.properties.putAll(properties);
    }



    public static AuthenticationManager getInstance() {
        return instance;
    }

    public void lockUser(String user) {
        String credentialsKey = getCredentialsKey(user);
        String password = properties.getProperty(credentialsKey);
        properties.setProperty(credentialsKey, '!' + password);
    }
}
