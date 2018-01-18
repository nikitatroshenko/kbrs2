package by.bsu.nikita.cryptonotepad.logic;

import java.util.Scanner;

/**
 * @author Nikita Atroshenko
 * @version 1.0
 */
public class Reader {

    public static final String INPUT = "files/input2.txt";

    public static String readFromFile(String path) {
        String lines = "";
        Scanner sc = null;
        try {
            System.out.println("System.getProperty(\"java.class.path\") = "
                    + System.getProperty("java.class.path")); // XXX
            sc = new Scanner(Reader.class.getClassLoader().getResourceAsStream(path));
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                lines += line + "\n";
            }
        } catch (Exception e) {
            return null;
        } finally {
            if (sc != null) {
                sc.close();
            }
        }
        return lines;
    }
}
