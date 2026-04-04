package pl.krypto;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static pl.krypto.AES.AESDecrypt;
import static pl.krypto.AES.AESEncrypt;
import static pl.krypto.KeySchedulers.generateRandomKey;

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
        String cypherText = cypherTextInput.getText();
        String key = keyInput.getText();

        if (selectedFile != null) {
            byte[] fileBytes = Files.readAllBytes(selectedFile.toPath());
            List<byte[]> fileChunks = new ArrayList<>();

            for (int i = 0; i < fileBytes.length; i += 16) {
                int limit = Math.min(i + 16, fileBytes.length);

                byte[] chunk = Arrays.copyOfRange(fileBytes, i, limit);
                fileChunks.add(chunk);
            }

            StringBuilder fileCypherString = new StringBuilder();

            for (byte[] b : fileChunks) {
                fileCypherString.append(AESEncrypt(b, key));
            }

            cypherTextOutput.setText(fileCypherString.toString());
        } else {
            List<String> cypherChunks = new ArrayList<>();

            for (int i = 0; i < cypherText.length(); i += 16) {
                int limit = Math.min(i + 16, cypherText.length());

                String chunk = cypherText.substring(i, limit);
                cypherChunks.add(chunk);
            }

            StringBuilder sb1 = new StringBuilder();

            for (String s : cypherChunks) {
                sb1.append(AESEncrypt(s, key));
            }

            cypherTextOutput.setText(sb1.toString());
        }
    }

    @FXML
    protected void onDecypherClick() {
        String decypherText = cypherTextOutput.getText();
        String key = keyInput.getText();

        List<String> decypherChunks = new ArrayList<>();

        for (int i = 0; i < decypherText.length(); i += 32) {
            int limit = Math.min(i + 32, decypherText.length());

            String chunk = decypherText.substring(i, limit);
            decypherChunks.add(chunk);
        }

        StringBuilder sb1 = new StringBuilder();

        for (String s : decypherChunks) {
            sb1.append(AESDecrypt(s, key));
        }

        cypherTextInput.setText(sb1.toString());
    }
}
