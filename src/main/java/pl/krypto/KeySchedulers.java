package pl.krypto;

import static pl.krypto.Constants.RCON;
import static pl.krypto.Constants.SBOX;

public class KeySchedulers {
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

    public static String generateRandomKey(int length) {
        byte[] key = new byte[length];

        long seed = System.nanoTime();

        long a = 1664525;
        long c = 1013904223;

        for (int i = 0; i < length; i++) {
            seed = (a * seed + c);

            key[i] = (byte) ((seed >> 24) & 0xFF);
        }

//        StringBuilder sb = new StringBuilder();
//        for (byte b : key) {
//            sb.append(String.format("%02X", b));
//        }
//
//        return sb.toString();

        return java.util.Base64.getEncoder().encodeToString(key);
    }

    public static byte[][] keySchedule128bit(byte[] key) {
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

    public static byte[][] keySchedule192bit(byte[] key) {
        byte[][] words = new byte[52][4];

        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 4; j++) {
                words[i][j] = key[i * 4 + j];
            }
        }

        for (int i = 6; i < 52; i++) {
            byte[] temp = words[i - 1].clone();

            if (i % 6 == 0) {
                temp = subWord(rotWord(temp));
                temp[0] = (byte) (temp[0] ^ (RCON[i / 6] & 0xFF));
            }

            for (int j = 0; j < 4; j++) {
                words[i][j] = (byte) (words[i - 6][j] ^ temp[j]);
            }
        }

        return words;
    }

    public static byte[][] keySchedule256bit(byte[] key) {
        byte[][] words = new byte[60][4];

        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 4; j++) {
                words[i][j] = key[i * 4 + j];
            }
        }

        for (int i = 8; i < 60; i++) {
            byte[] temp = words[i - 1].clone();

            if (i % 8 == 0) {
                temp = subWord(rotWord(temp));
                temp[0] = (byte) (temp[0] ^ (RCON[i / 8] & 0xFF));
            }

            if (i % 4 == 0 && i % 8 != 0) {
                temp = subWord(temp);
            }

            for (int j = 0; j < 4; j++) {
                words[i][j] = (byte) (words[i - 4][j] ^ temp[j]);
            }
        }

        return words;
    }
}
