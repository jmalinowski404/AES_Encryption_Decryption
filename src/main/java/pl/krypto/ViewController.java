package pl.krypto;

import javafx.fxml.FXML;
import javafx.scene.control.*;
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
    private Button saveCypherBtn;

    @FXML
    private Button saveDecypherBtn;

    private byte[] data;

    @FXML
    private Label infoLabel;

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
            infoLabel.setText("Załadowano plik: " + file.getName());
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

        if (key == null || key.trim().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Błąd walidacji");
            alert.setHeaderText("Brak klucza");
            alert.setContentText("Aby wykonać szyfrowanie lub deszyfrowanie, proszę wprowadzić klucz.");

            alert.showAndWait();
            return;
        }

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
            data = null;
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

            data = encryptedFileBytes;
            cypherTextOutput.setText(finalOutput);
            selectedFile = null;
        } else {
            data = null;
            String cypherText = cypherTextInput.getText();
            byte[] textBytes = cypherText.getBytes(StandardCharsets.UTF_8);
            byte[] paddedTextBytes = AES.addPadding(textBytes);
            byte[] encryptedTextBytes = new byte[paddedTextBytes.length];

            for (int i = 0; i < paddedTextBytes.length; i += 16) {
                byte[] chunk = new byte[16];
                System.arraycopy(paddedTextBytes, i, chunk, 0, 16);

                byte[] encryptedChunk = AESEncrypt(chunk, keySchedule, rounds);
                System.arraycopy(encryptedChunk, 0, encryptedTextBytes, i, 16);
            }

            data = encryptedTextBytes;
            String finalOutput = Base64.getEncoder().encodeToString(encryptedTextBytes);
            cypherTextOutput.setText(finalOutput);
        }
    }

    @FXML
    protected void onDecypherClick() throws IOException {
        String decypherText = cypherTextOutput.getText();

        String key = keyInput.getText();

        if (key == null || key.trim().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Błąd walidacji");
            alert.setHeaderText("Brak klucza");
            alert.setContentText("Aby wykonać szyfrowanie lub deszyfrowanie, proszę wprowadzić klucz.");

            alert.showAndWait();
            return;
        }

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
            data = null;
            byte[] encryptedFileBytes = Files.readAllBytes(selectedFile.toPath());
            byte[] decryptedFileBytes = new byte[encryptedFileBytes.length];

            for (int i = 0; i < encryptedFileBytes.length; i += 16) {
                byte[] chunk = new byte[16];
                System.arraycopy(encryptedFileBytes, i, chunk, 0, 16);

                byte[] decryptedChunk = AESDecrypt(chunk, keySchedule, rounds);
                System.arraycopy(decryptedChunk, 0, decryptedFileBytes, i, 16);
            }

            int paddingValue = decryptedFileBytes[decryptedFileBytes.length - 1] & 0xFF;
            int length = decryptedFileBytes.length;

            if (paddingValue > 0 && paddingValue <= 16) {
                length -= paddingValue;
            }

            cypherTextInput.setText(new String(decryptedFileBytes, 0, length, StandardCharsets.UTF_8));
            data = Arrays.copyOfRange(decryptedFileBytes, 0, length);
            selectedFile = null;
        } else {
            data = null;
            byte[] encryptedTextBytes = Base64.getDecoder().decode(decypherText);
            byte[] decryptedTextBytes = new byte[encryptedTextBytes.length];

            for (int i = 0; i < encryptedTextBytes.length; i += 16) {
                byte[] chunk = new byte[16];
                System.arraycopy(encryptedTextBytes, i, chunk, 0, 16);

                byte[] decryptedChunk = AESDecrypt(chunk, keySchedule, rounds);
                System.arraycopy(decryptedChunk, 0, decryptedTextBytes, i, 16);
            }

            int paddingValue = decryptedTextBytes[decryptedTextBytes.length - 1] & 0xFF;
            int textLength = decryptedTextBytes.length;

            if (paddingValue > 0 && paddingValue <= 16) {
                textLength -= paddingValue;
            }

            data = decryptedTextBytes;
            cypherTextInput.setText(new String(decryptedTextBytes, 0, textLength, StandardCharsets.UTF_8));
        }
    }

    @FXML
    protected void saveCypher() {
        saveFileToDisk(data, "encryption", saveCypherBtn);
    }

    @FXML
    protected void saveDecypher() {
        saveFileToDisk(data, "decryption", saveDecypherBtn);
    }

    protected void saveFileToDisk(byte[] data, String suggestedFileName, Button button) {
        FileChooser fileChoose = new FileChooser();
        fileChoose.setTitle("Zapisz plik jako...");

        fileChoose.setInitialFileName(suggestedFileName);

        fileChoose.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Pliki zaszyfrowane (*.enc)", "*.enc"),
                new FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );

        Stage stage = (Stage) button.getScene().getWindow();

        File savedFile = fileChoose.showSaveDialog(stage);

        if (savedFile != null) {
            try {
                Files.write(savedFile.toPath(), data);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
