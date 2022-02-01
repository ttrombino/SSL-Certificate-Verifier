package com.example.verifycertificate;

import androidx.appcompat.app.AppCompatActivity;

import android.graphics.Color;
import android.os.Bundle;
import android.os.StrictMode;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.IOException;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class MainActivity extends AppCompatActivity {

    private EditText xmlUrl;
    private Button xmlVerify;
    private TextView xmlResult;
    private TextView xmlMessage;
    private TextView xmlDomain;
    private ScrollView xmlScroll;
    private StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        StrictMode.setThreadPolicy(policy);
        xmlUrl = findViewById(R.id.editTextUrl);
        xmlVerify = findViewById(R.id.buttonVerify);
        xmlResult = findViewById(R.id.textViewResult);
        xmlMessage = findViewById(R.id.textViewMessage);
        xmlDomain = findViewById(R.id.textViewDomain);
        xmlScroll = findViewById(R.id.scrollView);

        xmlVerify.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String inputURL = xmlUrl.getText().toString();
                xmlMessage.setText("");
                xmlDomain.setText("Domain: " + inputURL);
                String validOutput = "";
                try {
                    validOutput = verifyURL(inputURL);
                }
                catch(SSLHandshakeException e){
                    String errString = "Error:\n" + e.getMessage();
                    xmlResult.setTextColor(Color.RED);
                    xmlResult.setText("Invalid Certificate");
                    xmlMessage.setText(errString);

                }
                catch(Exception e) {
                    String errString = "Error:\n" + e.getMessage();
                    xmlResult.setTextColor(Color.RED);
                    xmlResult.setText("Invalid Domain");
                    xmlMessage.setText(errString);
                }

                if(validOutput != "") {
                    xmlResult.setTextColor(Color.GREEN);
                    xmlResult.setText("Valid Certificate");
                    xmlMessage.setText(validOutput);
                }

            }
        });

    }

    private String verifyURL(String inputURL) throws IOException {
        String https = "https://";
        URL url = new URL(https + inputURL);
        HttpsURLConnection urlConnection = null;
        urlConnection = (HttpsURLConnection) url.openConnection();
        try {
            int status = urlConnection.getResponseCode();
        }
        finally {
        }
        String formattedCerts = formatCerts(urlConnection.getServerCertificates());
        urlConnection.disconnect();
        return formattedCerts;
    }

    private String formatCerts(Certificate[] certs) {
        StringBuilder buildCerts = new StringBuilder();
        buildCerts.append("Certificates:\n\n");
        for (int i = 0; i < certs.length; i = i + 1) {
            X509Certificate cert = (X509Certificate) certs[i];
            buildCerts.append(" " + (i+1) + ":\n");
            buildCerts.append("   Issuer: " + cert.getIssuerDN().toString() + "\n\n");
            buildCerts.append("   Expires: " + cert.getNotAfter().toString() + "\n\n\n");
        }

        return buildCerts.toString();
    }
}