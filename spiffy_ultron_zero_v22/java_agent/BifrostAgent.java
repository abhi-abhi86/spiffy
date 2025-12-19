
/**
 * Omega Kernel - Bifrost Java Agent
 * Portable P2P client for cross-platform connectivity
 * 
 * Supports: Windows, Linux, macOS, Android
 */

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;

public class BifrostAgent {

    private static final String VERSION = "v32.0";
    private static final int BUFFER_SIZE = 8192;
    // Shared secret for demo purposes (in production use ECDH)
    private static final String SHARED_SECRET = "BIFROST_OMEGA_KERNEL_AUTH_KEY_V1";

    private String serverHost;
    private int serverPort;
    private SocketChannel channel;
    private SecretKey aesKey;
    private volatile boolean running = false;

    public BifrostAgent(String host, int port) {
        this.serverHost = host;
        this.serverPort = port;
    }

    /**
     * Generate 10-digit Bifrost token from IP and port
     * Format: OOOPPPPPCC (IP octets + Port + Checksum)
     */
    public static String generateToken(String ip, int port) {
        try {
            String[] octets = ip.split("\\.");
            if (octets.length != 4)
                return "INVALID_IP";

            int octet3 = Integer.parseInt(octets[2]);
            int octet4 = Integer.parseInt(octets[3]);

            // Compress IP octets (3 digits)
            int ipComponent = (octet3 * 10 + octet4) % 1000;

            // Port component (5 digits)
            int portComponent = port % 100000;

            // Create base token
            String baseToken = String.format("%03d%05d", ipComponent, portComponent);

            // Calculate CRC8 checksum
            int checksum = calculateCRC8(baseToken) % 100;

            return baseToken + String.format("%02d", checksum);

        } catch (Exception e) {
            return "ERROR";
        }
    }

    /**
     * Resolve 10-digit token to IP and port
     */
    public static String[] resolveToken(String token, String baseSubnet) {
        if (token.length() != 10) {
            return new String[] { "0.0.0.0", "0" };
        }

        try {
            int ipComponent = Integer.parseInt(token.substring(0, 3));
            int portComponent = Integer.parseInt(token.substring(3, 8));
            int checksum = Integer.parseInt(token.substring(8, 10));

            // Decode IP octets
            int octet3 = ipComponent / 10;
            int octet4 = ipComponent % 10;

            String ip = baseSubnet + "." + octet3 + "." + octet4;

            return new String[] { ip, String.valueOf(portComponent) };

        } catch (Exception e) {
            return new String[] { "0.0.0.0", "0" };
        }
    }

    /**
     * Calculate CRC8 checksum
     */
    private static int calculateCRC8(String data) {
        int crc = 0x00;
        int polynomial = 0x07;

        for (byte b : data.getBytes()) {
            crc ^= b;
            for (int i = 0; i < 8; i++) {
                if ((crc & 0x80) != 0) {
                    crc = (crc << 1) ^ polynomial;
                } else {
                    crc <<= 1;
                }
            }
        }

        return crc & 0xFF;
    }

    /**
     * Connect to Bifrost server
     */
    public boolean connect() {
        try {
            System.out.println("🔗 Connecting to Bifrost server: " + serverHost + ":" + serverPort);

            channel = SocketChannel.open();
            channel.connect(new InetSocketAddress(serverHost, serverPort));
            channel.configureBlocking(false);

            System.out.println("✓ Connected successfully");

            // Use derived shared key for communication
            aesKey = generateAESKey();
            running = true;

            return true;

        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("✗ Connection failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Check if connected
     */
    public boolean isConnected() {
        return channel != null && channel.isOpen() && running;
    }

    /**
     * Send encrypted message
     */
    public void sendMessage(String message) {
        try {
            byte[] encrypted = encryptAES(message.getBytes("UTF-8"));
            ByteBuffer buffer = ByteBuffer.wrap(encrypted);

            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }

            // System.out.println("📤 Sent: " + message); // Optional: don't double print

        } catch (Exception e) {
            System.err.println("✗ Send failed: " + e.getMessage());
        }
    }

    /**
     * Receive encrypted message
     * Returns the message if received, null if no data, throws exception on
     * error/close
     */
    public String receiveMessage() throws IOException {
        try {
            if (!isConnected())
                return null;

            ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
            int bytesRead = channel.read(buffer);

            if (bytesRead == -1) {
                // Connection closed by server
                throw new IOException("Connection closed by server");
            }

            if (bytesRead > 0) {
                buffer.flip();
                byte[] data = new byte[buffer.remaining()];
                buffer.get(data);

                byte[] decrypted = decryptAES(data);
                String message = new String(decrypted, "UTF-8");

                System.out.println("\n📥 Received: " + message);
                System.out.print("> "); // Restore prompt
                return message;
            }

        } catch (Exception e) {
            if (e instanceof IOException)
                throw (IOException) e;
            System.err.println("✗ Receive decryption failed: " + e.getMessage());
        }

        return null;
    }

    /**
     * Generate AES key from Shared Secret
     */
    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        // Derive key from shared secret using SHA-256 (32 bytes = 256 bits)
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try {
            byte[] key = sha.digest(SHARED_SECRET.getBytes("UTF-8"));
            return new SecretKeySpec(key, "AES");
        } catch (UnsupportedEncodingException e) {
            // Should not happen
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Encrypt with AES-256-GCM
     */
    private byte[] encryptAES(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Combine IV + ciphertext
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return result;
    }

    /**
     * Decrypt with AES-256-GCM
     */
    private byte[] decryptAES(byte[] encrypted) throws Exception {
        if (encrypted.length < 12)
            throw new IllegalArgumentException("Invalid packet length");

        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[encrypted.length - 12];

        System.arraycopy(encrypted, 0, iv, 0, 12);
        System.arraycopy(encrypted, 12, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        return cipher.doFinal(ciphertext);
    }

    /**
     * Close connection
     */
    public void disconnect() {
        running = false;
        try {
            if (channel != null && channel.isOpen()) {
                channel.close();
                System.out.println("🔌 Disconnected from server");
            }
        } catch (IOException e) {
            System.err.println("✗ Disconnect error: " + e.getMessage());
        }
    }

    /**
     * Main entry point
     */
    public static void main(String[] args) {
        System.out.println("⚡ OMEGA KERNEL - BIFROST JAVA AGENT " + VERSION + " ⚡");
        System.out.println("================================================");

        // Test token system
        System.out.println("\n🔐 Testing 10-Digit Token System:");
        String testIP = "192.168.1.5";
        int testPort = 12345;

        String token = generateToken(testIP, testPort);
        System.out.println("Generated Token: " + token);

        String[] resolved = resolveToken(token, "192.168");
        System.out.println("Resolved: " + resolved[0] + ":" + resolved[1]);

        // Connect to server (if provided)
        if (args.length >= 2) {
            String host = args[0];
            int port = Integer.parseInt(args[1]);

            BifrostAgent agent = new BifrostAgent(host, port);

            if (agent.connect()) {

                // Start receiver thread
                Thread receiver = new Thread(() -> {
                    while (agent.isConnected()) {
                        try {
                            agent.receiveMessage();
                            Thread.sleep(100); // Prevent CPU spinning
                        } catch (IOException e) {
                            System.out.println("\n✗ Connection lost.");
                            agent.disconnect();
                            System.exit(0);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                });
                receiver.start();

                // Simple chat loop
                Scanner scanner = new Scanner(System.in);
                System.out.println("\n💬 Chat mode (type 'exit' to quit):");

                while (agent.isConnected()) {
                    System.out.print("> ");
                    String input = scanner.nextLine();

                    if (input.equalsIgnoreCase("exit")) {
                        break;
                    }

                    agent.sendMessage(input);
                }

                agent.disconnect();
                scanner.close();
                System.exit(0);
            }
        } else {
            System.out.println("\n📖 Usage: java BifrostAgent <host> <port>");
            System.out.println("Example: java BifrostAgent 192.168.1.5 55555");
        }
    }
}
