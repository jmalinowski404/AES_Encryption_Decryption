package pl.krypto;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static pl.krypto.AES.*;
import static pl.krypto.KeySchedulers.*;

public class ViewController {
    @FXML
    private TextArea cypherTextInput;

    @FXML
    private TextArea cypherTextOutput;

    @FXML
    private TextField keyInput;

    @FXML
    private ChoiceBox<String> keyLengthChoiceBox;

    @FXML
    private Button chooseFileBtn;

    private File selectedFile;

    @FXML
    protected void initialize() {
        keyLengthChoiceBox.getItems().addAll("128 bit", "192 bit", "256 bit");

        keyLengthChoiceBox.setValue("128 bit");
    }

    @FXML
    protected void onChooseFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz plik do zaszyfrowania/zdeszyfrowania");

        Stage stage = (Stage) chooseFileBtn.getScene().getWindow();

        File file = fileChooser.showOpenDialog(stage);

        if (file != null) {
            selectedFile = file;
        }
    }

    @FXML
    protected void onGenerateKey() {
        String selection = keyLengthChoiceBox.getValue();

        String key;

        switch(selection) {
            case "128 bit":
                key = generateRandomKey(16);
                break;

            case "192 bit":
                key = generateRandomKey(24);
                break;

            case "256 bit":
                key = generateRandomKey(32);
                break;

            default:
                key = generateRandomKey(16);
                break;
        }

        keyInput.setText(key);
    }

    @FXML
    protected void onCypherClick() throws IOException {
        String key = keyInput.getText();

        byte[] key_ = java.util.Base64.getDecoder().decode(key);
        byte[][] keySchedule;
        int rounds;

        switch(key_.length) {
            case 16:
                keySchedule = keySchedule128bit(key_);
                rounds = 10;
                break;

            case 24:
                keySchedule = keySchedule192bit(key_);
                rounds = 12;
                break;

            case 32:
                keySchedule = keySchedule256bit(key_);
                rounds = 14;
                break;

            default:
                keySchedule = keySchedule128bit(key_);
                rounds = 10;
                break;
        }

        if (selectedFile != null) {
            byte[] fileBytes = Files.readAllBytes(selectedFile.toPath());
            byte[] paddedFileBytes = addPadding(fileBytes);
            byte[] encryptedFileBytes = new byte[paddedFileBytes.length];

            for (int i = 0; i < paddedFileBytes.length; i += 16) {
                byte[] chunk = new byte[16];
                System.arraycopy(paddedFileBytes, i, chunk, 0, 16);

                byte[] encryptedChunk = AESEncrypt(chunk, keySchedule, rounds);
                System.arraycopy(encryptedChunk, 0, encryptedFileBytes, i, 16);
            }

            String finalOutput = Base64.getEncoder().encodeToString(encryptedFileBytes);

            cypherTextOutput.setText(finalOutput);
            selectedFile = null;
        } else {
            String cypherText = cypherTextInput.getText();
            byte[] textBytes = cypherText.getBytes(StandardCharsets.UTF_8);
            byte[] paddedTextBytes = AES.addPadding(textBytes);
            byte[] encryptedTextBytes = new byte[paddedTextBytes.length];

            for (int i = 0; i < cypherText.length(); i += 16) {
                byte[] chunk = new byte[16];
                System.arraycopy(paddedTextBytes, i, chunk, 0, 16);

                byte[] encryptedChunk = AESEncrypt(chunk, keySchedule, rounds);
                System.arraycopy(encryptedChunk, 0, encryptedTextBytes, i, 16);
            }

            String finalOutput = Base64.getEncoder().encodeToString(encryptedTextBytes);
            cypherTextOutput.setText(finalOutput);
        }
    }

    @FXML
    protected void onDecypherClick() {
        String decypherText = cypherTextOutput.getText();

        String key = keyInput.getText();
        byte[] key_ = java.util.Base64.getDecoder().decode(key);
        byte[][] keySchedule;
        int rounds;

        switch(key_.length) {
            case 16:
                keySchedule = keySchedule128bit(key_);
                rounds = 10;
                break;

            case 24:
                keySchedule = keySchedule192bit(key_);
                rounds = 12;
                break;

            case 32:
                keySchedule = keySchedule256bit(key_);
                rounds = 14;
                break;

            default:
                keySchedule = keySchedule128bit(key_);
                rounds = 10;
                break;
        }

        byte[] encryptedBytes = Base64.getDecoder().decode(decypherText);
        byte[] decryptedBytes = new byte[encryptedBytes.length];

        for (int i = 0; i < encryptedBytes.length; i += 16) {
            byte[] chunk = new byte[16];
            System.arraycopy(encryptedBytes, i, chunk, 0, 16);

            byte[] decryptedChunk = AESDecrypt(chunk, keySchedule, rounds);
            System.arraycopy(decryptedChunk, 0, decryptedBytes, i, 16);
        }

        int paddingValue = decryptedBytes[decryptedBytes.length - 1] & 0xFF;
        int textLength = decryptedBytes.length;

        if (paddingValue > 0 && paddingValue <= 16) {
            textLength -= paddingValue;
        }

        cypherTextInput.setText(new String(decryptedBytes, 0, textLength, StandardCharsets.UTF_8));
    }

    protected void saveFileToDisk(byte[] data) throws IOException {
        FileOutputStream fos = new FileOutputStream("decryption_result.bin");

        fos.write(data);
        fos.flush();
        fos.close();
    }
}
