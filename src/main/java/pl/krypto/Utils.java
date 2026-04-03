package pl.krypto;

public class Utils {
    public static byte galoisMult2(byte b) {
        int i = b & 0xFF;
        int result = i << 1;

        if ((i & 0x80) != 0) {
            result ^= 0x1B;
        }

        return (byte) result;
    }

    public static byte mult9(byte b) {
        byte b2 = galoisMult2(b);
        byte b4 = galoisMult2(b2);
        byte b8 = galoisMult2(b4);
        return (byte) (b8 ^ b);
    }

    public static byte mult11(byte b) {
        byte b2 = galoisMult2(b);
        byte b4 = galoisMult2(b2);
        byte b8 = galoisMult2(b4);
        return (byte) (b8 ^ b2 ^ b);
    }

    public static byte mult13(byte b) {
        byte b2 = galoisMult2(b);
        byte b4 = galoisMult2(b2);
        byte b8 = galoisMult2(b4);
        return (byte) (b8 ^ b4 ^ b);
    }

    public static byte mult14(byte b) {
        byte b2 = galoisMult2(b);
        byte b4 = galoisMult2(b2);
        byte b8 = galoisMult2(b4);
        return (byte) (b8 ^ b4 ^ b2);
    }

    public static String convertToHex(byte b) {
        char hex = (char) (b & 0xFF);
        return Integer.toHexString(hex);
    }

    public static byte[] hexStringToByteArray(String s) {
        String cleanString = s.replaceAll("\\s+", "");
        int len = cleanString.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(cleanString.charAt(i), 16) << 4) + Character.digit(cleanString.charAt(i+1), 16));
        }
        return data;
    }

    public static void printState(byte[][] state) {
        System.out.println("--------- Macierz State ---------");
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                System.out.printf("0x%02X ", state[row][col] & 0xFF);
            }
            System.out.println();
        }
        System.out.println("---------------------------------");
    }

    public static void printKeySchedule(byte[][] words) {
        System.out.println("\n=======================================================");
        System.out.println("       HARMONOGRAM PODKLUCZY (KEY SCHEDULE)    ");
        System.out.println("=======================================================");

        for (int i = 0; i < words.length; i++) {
            if (i % 4 == 0) {
                System.out.printf("\n--- RUNDA %02d ---\n", i / 4);
            }

            System.out.printf("w[%2d]: ", i);
            for (int j = 0; j < 4; j++) {
                System.out.printf("0x%02X ", words[i][j] & 0xFF);
            }

            System.out.print("  ");

            if ((i + 1) % 4 == 0) {
                System.out.println();
            }
        }
        System.out.println("=======================================================");
    }
}
