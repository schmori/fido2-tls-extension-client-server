package tls.sockets.server;

import java.sql.*;

public class FIDODatabase {

    private static final String filename = "src/main/java/tls/sockets/server/fido_database.db";

    public static void createDatabase() {
        String url = "jdbc:sqlite:" + filename; // in root directory

        String users = """
                CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR(64) NOT NULL PRIMARY KEY,
                user_name VARCHAR(50),
                display_name VARCHAR(50)
                );""";

        String credentials = """
                CREATE TABLE IF NOT EXISTS credentials (
                credential_id VARCHAR(100) NOT NULL PRIMARY KEY,
                public_key VARCHAR(100),
                user_handle VARCHAR(64),
                FOREIGN KEY (user_handle) REFERENCES users(user_id)
                );""";

        try (Connection conn = DriverManager.getConnection(url); Statement statement = conn.createStatement()) {
            if (statement != null) {
                DatabaseMetaData meta = conn.getMetaData();
                System.out.println("The driver name is " + meta.getDriverName());
                System.out.println("A new database '" + filename + "' has been created.");

                // add tables
                statement.execute(users);
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
                    INSERT OR IGNORE INTO users(user_id,user_name,display_name) VALUES (?,?,?)
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

    public static void insertCredential(String credentialId, String publicKey, String user_id) {
        String sql = """
                    INSERT OR IGNORE INTO credentials(credential_id,public_key,user_handle) VALUES (?,?,?)
                    """;

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, credentialId);
            pstmt.setString(2, publicKey);
            pstmt.setString(3, user_id);
            pstmt.executeUpdate();
            System.out.println("A new credential was added to database '" + filename + "'.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getPublicKey(String user_id) {
        var sql = """
                SELECT public_key FROM credentials WHERE user_handle=?
        """;

        String publicKey = null;
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, user_id);

            try {
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        publicKey = rs.getString("public_key");
                    }
                }
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        return publicKey;
    }
}
