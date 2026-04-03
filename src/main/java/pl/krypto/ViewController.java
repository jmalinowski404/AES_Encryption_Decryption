package pl.krypto;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

import java.util.ArrayList;
import java.util.List;

import static pl.krypto.AES.AESDecrypt;
import static pl.krypto.AES.AESEncrypt;

public class ViewController {
    @FXML
    private TextArea cypherTextInput;

    @FXML
    private TextArea cypherTextOutput;

    @FXML
    private TextField keyInput;

    @FXML
    protected void onCypherClick() {
        String cypherText = cypherTextInput.getText();
        String key = keyInput.getText();

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
