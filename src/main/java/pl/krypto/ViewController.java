package pl.krypto;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

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

        String result = AESEncrypt(cypherText, key);

        cypherTextOutput.setText(result);
    }

    @FXML
    protected void onDecypherClick() {
        String decypherText = cypherTextOutput.getText();
        String key = keyInput.getText();

        String result = AESDecrypt(decypherText, key);

        cypherTextInput.setText(result);
    }
}
