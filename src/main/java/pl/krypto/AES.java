package pl.krypto;

import java.nio.charset.StandardCharsets;

public class AES {
    private static final int[] RCON = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    private static final int[] SBOX = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    private static byte[] rotWord(byte[] word) {
        byte[] w = word.clone();
        w[0] = word[1];
        w[1] = word[2];
        w[2] = word[3];
        w[3] = word[0];

        return w;
    }

    private static byte[] subWord(byte[] word) {
        byte[] w = word.clone();
        for (int i = 0; i < word.length; i++) {
            int index = word[i] & 0xFF;
            byte substituted = (byte) SBOX[index];
            w[i] = substituted;
        }

        return w;
    }

    private static byte galoisMult2(byte b) {
        int i = b & 0xFF;
        int result = i << 1;

        if ((i & 0x80) != 0) {
            result ^= 0x1B;
        }

        return (byte) result;
    }

    private static byte[][] SubBytes(byte[][] matrix) {
        byte[][] m = matrix.clone();

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                m[i][j] = (byte) SBOX[matrix[i][j] & 0xFF];
            }
        }

        return m;
    }

    private static byte[][] ShiftRows(byte[][] matrix) {
        byte[][] m = matrix.clone();

        m[1][0] = matrix[1][1];
        m[1][1] = matrix[1][2];
        m[1][2] = matrix[1][3];
        m[1][3] = matrix[1][0];

        m[2][0] = matrix[2][2];
        m[2][1] = matrix[2][3];
        m[2][2] = matrix[2][0];
        m[2][3] = matrix[2][1];

        m[3][0] = matrix[3][3];
        m[3][1] = matrix[3][0];
        m[3][2] = matrix[3][1];
        m[3][3] = matrix[3][2];

        return m;
    }

    private static byte[][] MixColumns(byte[][] matrix) {
        byte[][] result = new byte[4][4];

        for (int c = 0; c < 4; c++) {
            byte s0 = matrix[0][c];
            byte s1 = matrix[1][c];
            byte s2 = matrix[2][c];
            byte s3 = matrix[3][c];

            result[0][c] = (byte) (galoisMult2(s0) ^ galoisMult2(s1) ^ s1 ^ s2 ^ s3);
            result[1][c] = (byte) (s0 ^ galoisMult2(s1) ^ galoisMult2(s2) ^ s2 ^ s3);
            result[2][c] = (byte) (s0 ^ s1 ^ galoisMult2(s2) ^ galoisMult2(s3) ^ s3);
            result[3][c] = (byte) (galoisMult2(s0) ^ s0 ^ s1 ^ s2 ^ galoisMult2(s3));
        }

        return result;
    }

    private static String convertToHex(byte b) {
        char hex = (char) (b & 0xFF);
        return Integer.toHexString(hex);
    }

    private static void printState(byte[][] state) {
        System.out.println("--------- Macierz State ---------");
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                // Zmieniono na format 0x00
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

    private static byte[] addPadding(byte[] bytes) {
        int blockSize = 16;
        int paddingNeeded = blockSize - bytes.length;

        byte[] paddedBytes = new byte[bytes.length + paddingNeeded];

        System.arraycopy(bytes, 0, paddedBytes, 0, bytes.length);

        for (int i = bytes.length; i < paddedBytes.length; i++) {
            paddedBytes[i] = (byte) paddingNeeded;
        }

        return paddedBytes;
    }

    private static byte[][] fillStateMatrix(byte[] bytes) {
        byte[][] State = new byte[4][4];
        int index = 0;
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                State[row][col] = bytes[index++];
            }
        }

        return State;
    }

    private static byte[][] keySchedule128bit(byte[] key) {
        byte[][] words = new byte[44][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                words[i][j] = key[i * 4 + j];
            }
        }

        for (int i = 4; i < 44; i++) {
            byte[] temp = words[i - 1].clone();

            if (i % 4 == 0) {
                temp = subWord(rotWord(temp));
                temp[0] = (byte) (temp[0] ^ (RCON[i / 4] & 0xFF));
            }

            for (int j = 0; j < 4; j++) {
                words[i][j] = (byte) (words[i - 4][j] ^ temp[j]);
            }
        }

        return words;
    }

    private static byte[][] AddRoundKey(byte[][] state, byte[][] key, int roundIndex) {
        byte[][] result = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            byte[] word = key[roundIndex * 4 + i];

            for (int j = 0; j < 4; j++) {
                result[j][i] = (byte) (state[j][i] ^ word[j]);
            }
        }

        return result;
    }

    public static String AESAlgorithm(String input) {
        StringBuilder sb = new StringBuilder();
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] paddedInput = addPadding(inputBytes);
        byte[][] State = fillStateMatrix(paddedInput);

        byte[] key_ = "bloodbehindbeach".getBytes();
        byte[][] key = keySchedule128bit(key_);

        State = AddRoundKey(State, key, 0);

        for (int i = 1; i < 10; i++) {
            State = SubBytes(State);
            State = ShiftRows(State);
            State = MixColumns(State);
            State = AddRoundKey(State, key, i);
        }

        State = SubBytes(State);
        State = ShiftRows(State);
        State = AddRoundKey(State, key, 10);

        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                sb.append(String.format("%02X", State[row][col] & 0xFF));
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) {

    }
}
