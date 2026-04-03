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
}
