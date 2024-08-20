package tls.database;

import com.yubico.webauthn.data.ByteArray;

import java.sql.*;

public class Database {

    private static final String filename = "fido_database.db";

    public static void createDatabase() {
        String url = "jdbc:sqlite:" + filename; // in root directory

        String users = """
                CREATE TABLE IF NOT EXISTS users (
                user_id BINARY(64) NOT NULL PRIMARY KEY,
                user_name VARCHAR(50),
                display_name VARCHAR(50)
                );""";

        String certificates = """
                CREATE TABLE IF NOT EXISTS certificates (
                user_id BINARY(64) NOT NULL PRIMARY KEY,
                certificate VARCHAR(65536) NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
                );""";

        String credentials = """
                CREATE TABLE IF NOT EXISTS credentials (
                credential_id VARBINARY(65536) NOT NULL PRIMARY KEY,
                aaguid BINARY(16) NOT NULL,
                public_key VARBINARY(131072) NOT NULL,
                signature_counter INTEGER NOT NULL DEFAULT 0,
                user_id BINARY(64) NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
                );""";

        try (Connection conn = DriverManager.getConnection(url); Statement statement = conn.createStatement()) {
            if (statement != null) {
                DatabaseMetaData meta = conn.getMetaData();
                System.out.println("The driver name is " + meta.getDriverName());
                System.out.println("A new database '" + filename + "' has been created.");

                // add tables
                statement.execute(users);
                statement.execute(certificates);
                statement.execute(credentials);
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    private static Connection connect() {
        String url = "jdbc:sqlite:" + filename;
        Connection conn;
        try {
            conn = DriverManager.getConnection(url);
            System.out.println("Connected to database '" + filename + "'.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return conn;
    }

    public static void insertUser(String userId, String username, String displayname) {
        String sql = """
                    INSERT INTO users(user_id,user_name,display_name) VALUES (?,?,?)
                    """;

        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, userId);
            pstmt.setString(2, username);
            pstmt.setString(3, displayname);
            pstmt.executeUpdate();
            System.out.println("A new user was added to database '" + filename + "'.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void insertCertificate(ByteArray userId, String certificate) {
        String sql = """
                    INSERT INTO certificates(user_id,certificate) VALUES (?,?)
                    """;

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setBytes(1, userId.getBytes());
            pstmt.setString(2, certificate);
            pstmt.executeUpdate();
            System.out.println("A new certificate was added to database '" + filename + "'.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void insertCredential(ByteArray credentialId, ByteArray aaguid, ByteArray publicKey, int signatureCounter, ByteArray userId) {
        String sql = """
                    INSERT INTO certificates(credential_id,aaguid,public_key, signature_counter,user_id) VALUES (?,?,?,?,?)
                    """;

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setBytes(1, credentialId.getBytes());
            pstmt.setBytes(2, aaguid.getBytes());
            pstmt.setBytes(3, publicKey.getBytes());
            pstmt.setInt(4, signatureCounter);
            pstmt.setBytes(5, userId.getBytes());
            pstmt.executeUpdate();
            System.out.println("A new credential was added to database '" + filename + "'.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
