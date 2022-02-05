package com.example.verifycertificate;

import androidx.appcompat.app.AppCompatActivity;

import android.content.res.Resources;
import android.graphics.Color;
import android.os.Bundle;
import android.os.StrictMode;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public class MainActivity extends AppCompatActivity {

    private EditText xmlUrl;
    private Button xmlVerify;
    private TextView xmlResult;
    private TextView xmlMessage;
    private TextView xmlDomain;
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

        xmlVerify.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String inputUrl = xmlUrl.getText().toString();
                xmlMessage.setText("");
                xmlDomain.setText("Domain: " + inputUrl);
                String validOutput = "";
                try {
                    validOutput = getCertificates(inputUrl);
                }
                catch(SSLHandshakeException e){
                    String errString = "Error:\n" + e.getMessage();
                    xmlResult.setTextColor(Color.RED);
                    xmlResult.setText("Invalid");
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
                    xmlResult.setText("Valid");
                    xmlMessage.setText(validOutput);
                }

            }
        });

    }

    /**
     * Returns a String representation of the given URL's Certificate Chain.
     * Throws an IOException if there are any connection errors.
     */
    private String getCertificates(String inputURL) throws IOException, CertificateException, CRLException {
        String https = "https://";
        String formattedCerts = "";
        URL url = new URL(https + inputURL);
        HttpsURLConnection urlConnection = null;
        urlConnection = (HttpsURLConnection) url.openConnection();
        try {
            int status = urlConnection.getResponseCode();
            Certificate[] certs = urlConnection.getServerCertificates();
            checkForRevocation(certs);

            formattedCerts = formatCerts(certs);
        }
        finally {
            urlConnection.disconnect();
        }
        return formattedCerts;
    }

    private void checkForRevocation(Certificate[] certs) throws CertificateException, CRLException, SSLHandshakeException {

        InputStream inStream = getResources().openRawResource(R.raw.rmixedsha);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) cf.generateCRL(inStream);
        for(Certificate cert : certs) {
//            X509Certificate cert = (X509Certificate) c;

            if (crl.isRevoked(cert)){
                throw new SSLHandshakeException("Certificate Revoked");
            }
        }

    }

    /**
     * Takes an ordered array of Certificates and formats the necessary
     * information into the returned String.
     */
    private static String formatCerts(Certificate[] certs) {
        StringBuilder buildCerts = new StringBuilder();
        buildCerts.append("Certificate Chain:\n\n");
        for (int i = 0; i < certs.length; i = i + 1) {
            X509Certificate cert = (X509Certificate) certs[i];
            buildCerts.append(" ").append(i + 1).append(":\n");
            buildCerts.append("   Issuer: ").append(cert.getIssuerDN().toString()).append("\n\n");
            buildCerts.append("   Expires: ").append(cert.getNotAfter().toString()).append("\n\n\n");
        }
        return buildCerts.toString();
    }
}