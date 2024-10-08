package tls.sockets.client;

import java.sql.*;

public class CTAP2Database {

    private static final String filename = "src/main/java/tls/sockets/client/ctap_database.db";

    public static void createDatabase() {
        String url = "jdbc:sqlite:" + filename; // in root directory

        String users = """
                CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR(64) NOT NULL PRIMARY KEY,
                key_pair BINARY(256)
                );""";

        try (Connection conn = DriverManager.getConnection(url); Statement statement = conn.createStatement()) {
            if (statement != null) {
                DatabaseMetaData meta = conn.getMetaData();
                System.out.println("The driver name is " + meta.getDriverName());
                System.out.println("A new database '" + filename + "' has been created.");

                // add tables
                statement.execute(users);
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

    public static void insertUser(String userId, byte[] keyPair) {
        String sql = """
                    INSERT OR IGNORE INTO users(user_id,key_pair) VALUES (?,?)
                    """;

        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, userId);
            pstmt.setBytes(2, keyPair);
            pstmt.executeUpdate();
            System.out.println("A new user was added to database '" + filename + "'.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getKeyPair(String user_id) {
        var sql = """
                SELECT key_pair FROM users WHERE user_id=?
        """;

        byte[] keyPair = null;
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, user_id);

            try {
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        keyPair = rs.getBytes("key_pair");
                    }
                }
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        return keyPair;
    }
}
