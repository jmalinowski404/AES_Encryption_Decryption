package pl.krypto;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;

import static pl.krypto.AES.AESAlgorithm;

public class ViewController {
    @FXML
    private TextArea cypherTextInput;

    @FXML
    private TextArea cypherTextOutput;

    @FXML
    protected void onCypherClick() {
        String plainText = cypherTextInput.getText();

        String result = AESAlgorithm(plainText);

        cypherTextOutput.setText(result);
    }
}
