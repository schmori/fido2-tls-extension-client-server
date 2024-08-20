package tls.utility;

import java.io.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CTAP2 {
    public static String clientData;
    public static String authData;
    public static String signature;
    public static String rpIdHash;
    public static String counter;
    public static String credentialData;

    public static void doCTAP2(String pubCredString) {
        // Starte das Python-Skript
        // prints aus dem python-skript werden nicht in echtzeit angezeigt sondern erst nachdem der Prozess beendet ist
        try {
            System.out.println("Touch your authenticator device now...");
            ProcessBuilder processBuilder = new ProcessBuilder("python", "C:\\Users\\Lenovo\\Documents\\Uni\\Masterarbeit\\FIDO2-TLS-integration\\src\\main\\java\\tls\\utility\\fido2-do-ctap.py", pubCredString);
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            BufferedReader inputStreamReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = inputStreamReader.readLine()) != null) {
                System.out.println(line);
                if (line.contains("CLIENTDATA")) {
                    clientData = Stream.of(line.split(" "))
                            .filter(word -> !word.contains("CLIENTDATA"))
                            .collect(Collectors.joining());
                }

                if (line.contains("AUTHDATA")) {
                    authData = Stream.of(line.split(" "))
                            .filter(word -> !word.contains("AUTHDATA"))
                            .collect(Collectors.joining());
                }

                if (line.contains("SIGNATURE")) {
                    signature = Stream.of(line.split(" "))
                            .filter(word -> !word.contains("SIGNATURE"))
                            .collect(Collectors.joining());
                }

                if (line.contains("RPIDHASH")) {
                    rpIdHash = Stream.of(line.split(" "))
                            .filter(word -> !word.contains("RPIDHASH"))
                            .collect(Collectors.joining());
                }
                if (line.contains("COUNTER")) {
                    counter = Stream.of(line.split(" "))
                            .filter(word -> !word.contains("COUNTER"))
                            .collect(Collectors.joining());
                }
                if (line.contains("CREDENTIALDATA")) {
                    credentialData = Stream.of(line.split(" "))
                            .filter(word -> !word.contains("CREDENTIALDATA"))
                            .collect(Collectors.joining());
                }
            }

            // Warte auf das Ende des Prozesses
            int exitCode = process.waitFor();
            System.out.println("Python script finished with exit code: " + exitCode);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}