package pl.krypto;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static pl.krypto.Constants.*;
import static pl.krypto.KeySchedulers.*;
import static pl.krypto.Utils.*;

public class AES {
    private static byte[][] SubBytes(byte[][] matrix) {
        byte[][] m = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                m[i][j] = (byte) SBOX[matrix[i][j] & 0xFF];
            }
        }

        return m;
    }

    private static byte[][] InvSubBytes(byte[][] matrix) {
        byte[][] m = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                m[i][j] = (byte) INVSBOX[matrix[i][j] & 0xFF];
            }
        }

        return m;
    }

    private static byte[][] ShiftRows(byte[][] matrix) {
        byte[][] m = new byte[4][4];

        m[0][0] = matrix[0][0];
        m[0][1] = matrix[0][1];
        m[0][2] = matrix[0][2];
        m[0][3] = matrix[0][3];

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

    private static byte[][] InvShiftRows(byte[][] matrix) {
        byte[][] m = new byte[4][4];

        m[0][0] = matrix[0][0];
        m[0][1] = matrix[0][1];
        m[0][2] = matrix[0][2];
        m[0][3] = matrix[0][3];

        m[1][0] = matrix[1][3];
        m[1][1] = matrix[1][0];
        m[1][2] = matrix[1][1];
        m[1][3] = matrix[1][2];

        m[2][0] = matrix[2][2];
        m[2][1] = matrix[2][3];
        m[2][2] = matrix[2][0];
        m[2][3] = matrix[2][1];

        m[3][0] = matrix[3][1];
        m[3][1] = matrix[3][2];
        m[3][2] = matrix[3][3];
        m[3][3] = matrix[3][0];

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

    private static byte[][] InvMixColumns(byte[][] matrix) {
        byte[][] result = new byte[4][4];

        for (int col = 0; col < 4; col++) {
            byte s0 = matrix[0][col];
            byte s1 = matrix[1][col];
            byte s2 = matrix[2][col];
            byte s3 = matrix[3][col];

            result[0][col] = (byte) (mult14(s0) ^ mult11(s1) ^ mult13(s2) ^ mult9(s3));
            result[1][col] = (byte) (mult9(s0)  ^ mult14(s1) ^ mult11(s2) ^ mult13(s3));
            result[2][col] = (byte) (mult13(s0) ^ mult9(s1)  ^ mult14(s2) ^ mult11(s3));
            result[3][col] = (byte) (mult11(s0) ^ mult13(s1) ^ mult9(s2)  ^ mult14(s3));
        }

        return result;
    }

    public static byte[] addPadding(byte[] bytes) {
        int blockSize = 16;

        int paddingNeeded = blockSize - (bytes.length % blockSize);

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

    public static byte[] AESEncrypt(byte[] inputBytes, byte[][] keySchedule, int rounds) {
        byte[][] State = fillStateMatrix(inputBytes);

        State = AddRoundKey(State, keySchedule, 0);

        for (int i = 1; i < rounds; i++) {
            State = SubBytes(State);
            State = ShiftRows(State);
            State = MixColumns(State);
            State = AddRoundKey(State, keySchedule, i);
        }

        State = SubBytes(State);
        State = ShiftRows(State);
        State = AddRoundKey(State, keySchedule, rounds);

        byte[] encryptedBlock = new byte[16];
        int index = 0;
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                encryptedBlock[index++] = State[row][col];
            }
        }
        return encryptedBlock;
    }

    public static byte[] AESDecrypt(byte[] inputBytes, byte[][] keySchedule, int rounds) {
        byte[][] State = fillStateMatrix(inputBytes);

        State = AddRoundKey(State, keySchedule, rounds);

        for (int i = rounds - 1; i >= 1; i--) {
            State = InvShiftRows(State);
            State = InvSubBytes(State);
            State = AddRoundKey(State, keySchedule, i);
            State = InvMixColumns(State);
        }

        State = InvShiftRows(State);
        State = InvSubBytes(State);
        State = AddRoundKey(State, keySchedule, 0);

        byte[] decryptedBytes = new byte[16];
        int index = 0;
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                decryptedBytes[index++] = State[row][col];
            }
        }

        return decryptedBytes;
    }

    public static void main(String[] args) {

    }
}
