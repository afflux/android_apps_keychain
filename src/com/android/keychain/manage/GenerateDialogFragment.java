
package com.android.keychain.manage;

import android.app.DialogFragment;
import android.app.ProgressDialog;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.Credentials;
import android.security.KeyStore;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.android.keychain.CryptOracleService;
import com.android.keychain.R;
import com.android.org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

@SuppressWarnings("deprecation")
public class GenerateDialogFragment extends DialogFragment implements OnClickListener {
    private class GeneratePKTask extends AsyncTask<Void, Integer, Boolean> {

        private final String alias;
        private final Date endDate;
        private final KeyPairGenerator keyPairGenerator;
        private final ProgressDialog pd = new ProgressDialog(mContext);
        private final BigInteger serial;
        private final Date startDate;
        private final X500Principal subject;

        /**
         * @param alias key identifier for use in subsequent operations
         * @param algorithm key algorithm. <i>only RSA supported for now</i>
         * @param keysize
         * @param endDate
         * @param mProgressDialog
         * @see KeyPairGenerator
         * @throws NoSuchAlgorithmException if the given algorithm does not
         *             exist
         * @throws NoSuchProviderException
         */
        public GeneratePKTask(String alias, String algorithm, int keysize, Date endDate)
                throws NoSuchAlgorithmException, NoSuchProviderException {
            this.alias = alias;
            this.endDate = endDate;
            this.subject = new X500Principal("cn=" + alias);
            this.serial = BigInteger.ONE;
            this.startDate = new Date();

            this.keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
                    CryptOracleService.DEFAULT_PROVIDER);
            this.keyPairGenerator.initialize(keysize);
        }

        /**
         * Largely based on {@link android.security.AndroidKeyPairGenerator}
         * 
         * @throws IllegalStateException if generating the certificate failed
         */
        @Override
        protected Boolean doInBackground(Void... params) throws IllegalStateException {
            publishProgress(R.string.generate_keypair);
            // generate key pair
            KeyPair keyPair = this.keyPairGenerator.genKeyPair();

            PrivateKey privKey = keyPair.getPrivate();
            PublicKey pubKey = keyPair.getPublic();

            // prepate certificate
            final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.setPublicKey(pubKey);
            certGen.setSerialNumber(this.serial);
            certGen.setSubjectDN(this.subject);
            certGen.setIssuerDN(this.subject);
            certGen.setNotBefore(this.startDate);
            certGen.setNotAfter(this.endDate);

            String keyAlgo = privKey.getAlgorithm();
            String sigAlgo;

            if ("RSA".equals(keyAlgo))
                sigAlgo = "sha1WithRSA";
            else if ("DSA".equals(keyAlgo))
                sigAlgo = "sha1WithDSA";
            else if ("EC".equals(keyAlgo) || "ECDSA".equals(keyAlgo))
                sigAlgo = "sha1WithECDSA";
            else
                throw new IllegalArgumentException("can't handle keyAlgo=" + keyAlgo);

            certGen.setSignatureAlgorithm(sigAlgo);

            publishProgress(R.string.generate_certificate);
            final X509Certificate cert;
            try {
                // self-sign certificate
                cert = certGen.generate(privKey);
            } catch (Exception e) {
                deleteAllTypesForAlias(this.alias);
                throw new IllegalStateException("Can't generate certificate", e);
            }

            byte[] certBytes;
            try {
                // convert certificate
                certBytes = Credentials.convertToPem(cert);
            } catch (CertificateEncodingException e) {
                deleteAllTypesForAlias(this.alias);
                throw new IllegalStateException("Can't get encoding of certificate", e);
            } catch (IOException e) {
                deleteAllTypesForAlias(this.alias);
                throw new IllegalStateException("Can't get encoding of certificate", e);
            }

            // store
            return GenerateDialogFragment.this.mKeyStore.put(CryptOracleService.USER_PRIVATE_KEY
                    + this.alias, privKey.getEncoded())
                    &&
                    GenerateDialogFragment.this.mKeyStore.put(CryptOracleService.USER_CERTIFICATE
                            + this.alias, certBytes);
        }

        @Override
        protected void onPostExecute(Boolean result) {
            this.pd.dismiss();
            if (result == true) {
                Toast.makeText(mContext, mContext.getString(R.string.cert_is_added, this.alias),
                        Toast.LENGTH_LONG).show();
                mContext.reloadData();
            } else {
                Toast.makeText(mContext, mContext.getString(R.string.cert_not_saved, this.alias),
                        Toast.LENGTH_LONG).show();
            }
        }

        @Override
        protected void onPreExecute() {
            this.pd.setMessage(mContext.getString(R.string.generate_start));
            this.pd.setIndeterminate(true);
            this.pd.setCancelable(false);
            this.pd.show();
        }

        @Override
        protected void onProgressUpdate(Integer... values) {
            this.pd.setMessage(mContext.getString(values[0]));
        }
    }

    private class GenerateSymTask extends AsyncTask<Void, Integer, Boolean> {

        private final String alias;
        private final KeyGenerator keyGenerator;
        private final ProgressDialog pd = new ProgressDialog(mContext);

        /**
         * @param alias key identifier for use in subsequent operations
         * @param algorithm key algorithm. <i>only RSA supported for now</i>
         * @param keysize
         * @param endDate
         * @param mProgressDialog
         * @see KeyPairGenerator
         * @throws NoSuchAlgorithmException if the given algorithm does not
         *             exist
         * @throws NoSuchProviderException
         */
        public GenerateSymTask(String alias, String algorithm, int keysize)
                throws NoSuchAlgorithmException, NoSuchProviderException {
            this.alias = alias;

            this.keyGenerator = KeyGenerator.getInstance(algorithm,
                    CryptOracleService.DEFAULT_PROVIDER);
            this.keyGenerator.init(keysize);
        }

        /**
         * Largely based on {@link android.security.AndroidKeyPairGenerator}
         * 
         * @throws IllegalStateException if generating the certificate failed
         */
        @Override
        protected Boolean doInBackground(Void... params) throws IllegalStateException {
            publishProgress(R.string.generate_secret);
            // generate key pair
            SecretKey key = this.keyGenerator.generateKey();

            // store
            return GenerateDialogFragment.this.mKeyStore.put(CryptOracleService.USER_SYMKEY
                    + this.alias, key.getEncoded());
        }

        @Override
        protected void onPostExecute(Boolean result) {
            this.pd.dismiss();
            if (result == true) {
                Toast.makeText(mContext, mContext.getString(R.string.cert_is_added, this.alias),
                        Toast.LENGTH_LONG).show();
                mContext.reloadData();
            } else {
                Toast.makeText(mContext, mContext.getString(R.string.cert_not_saved, this.alias),
                        Toast.LENGTH_LONG).show();
            }
        }

        @Override
        protected void onPreExecute() {
            this.pd.setMessage(mContext.getString(R.string.generate_start));
            this.pd.setIndeterminate(true);
            this.pd.setCancelable(false);
            this.pd.show();
        }

        @Override
        protected void onProgressUpdate(Integer... values) {
            this.pd.setMessage(mContext.getString(values[0]));
        }

    }

    private static final int DEFAULT_KEY_SIZE = 2048;
    private static final int DEFAULT_LIFETIME_YEARS = 5;

    static final String TAG = "GenerateDialogFragment";

    private Spinner algorithmSelector;
    private final KeySelectListActivity mContext;
    private final DateFormat dateFormat;
    private TextView errorView;
    private TextView expiryDateView;
    private TextView keySizeView;
    private TextView nameView;

    private KeyStore mKeyStore = KeyStore.getInstance();

    public GenerateDialogFragment(KeySelectListActivity ctx) {
        mContext = ctx;
        dateFormat = android.text.format.DateFormat.getDateFormat(ctx);
    }

    /**
     * @author see {@link Credentials}
     */
    private boolean deleteAllTypesForAlias(String alias) {
        /*
         * Make sure every type is deleted. There can be all three types, so
         * don't use a conditional here.
         */
        return this.mKeyStore.delKey(CryptOracleService.USER_PRIVATE_KEY + alias)
                | this.mKeyStore.delete(CryptOracleService.USER_CERTIFICATE + alias);
    }

    @Override
    public void onClick(View v) {
        // read specified values
        String algorithm = (String) this.algorithmSelector.getSelectedItem();
        String alias = this.nameView.getText().toString();
        String keySizeString = this.keySizeView.getText().toString();
        String expiryDateString = this.expiryDateView.getText().toString();

        boolean symmetric = isSymmetricAlgo(algorithm);

        int keySize;
        if (mKeyStore.contains(CryptOracleService.USER_SYMKEY + alias)
                || mKeyStore.contains(CryptOracleService.USER_CERTIFICATE
                        + alias))
            showError(R.string.alias_in_use);

        try {
            // parse key size
            keySize = Integer.parseInt(keySizeString);
        } catch (NumberFormatException e) {
            showError(R.string.invalid_key_size, e.getLocalizedMessage());
            return;
        }

        try {
            // verify key size
            KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm,
                    CryptOracleService.DEFAULT_PROVIDER);
            gen.initialize(keySize);
        } catch (GeneralSecurityException e) {
            showError(R.string.invalid_key_size, e.getLocalizedMessage());
        }

        Date expiryDate = null;
        if (!symmetric) {
            try {
                // parse date
                expiryDate = this.dateFormat.parse(expiryDateString);
                if (!expiryDate.after(new Date()))
                    showError(R.string.invalid_date, R.string.invalid_past_date);
            } catch (ParseException e) {
                showError(R.string.invalid_date, e.getLocalizedMessage());
                return;
            }
        }

        try {
            AsyncTask<Void, Integer, Boolean> t;
            if (symmetric)
                t = new GenerateSymTask(alias, algorithm, keySize);
            else
                t = new GeneratePKTask(alias, algorithm, keySize, expiryDate);
            dismissDialog();
            // start key generation in background
            t.execute();
        } catch (NoSuchAlgorithmException e) {
            showError(R.string.invalid_algorithm, e.getLocalizedMessage());
            return;
        } catch (NoSuchProviderException e) {
            showError(R.string.invalid_algorithm, e.getLocalizedMessage());
            return;
        }
    }

    private boolean isSymmetricAlgo(String algorithm) {
        return "AES".equals(algorithm);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.generate_cert_dialog, container, false);

        getDialog().setTitle(R.string.generate_dialog_title);

        this.nameView = (TextView) v.findViewById(R.id.credential_name);
        this.errorView = (TextView) v.findViewById(R.id.error);

        this.algorithmSelector = (Spinner) v.findViewById(R.id.algorithm);
        this.algorithmSelector.setSelection(0);

        this.keySizeView = (TextView) v.findViewById(R.id.key_size);
        this.keySizeView.setText(Integer.toString(DEFAULT_KEY_SIZE));

        Date expiryDate = new Date();
        expiryDate.setYear(expiryDate.getYear() + DEFAULT_LIFETIME_YEARS);

        this.expiryDateView = (TextView) v.findViewById(R.id.expiry_date);
        this.expiryDateView.setText(this.dateFormat.format(expiryDate));

        final Button confirm = (Button) v.findViewById(R.id.generate_button);
        confirm.setOnClickListener(this);
        
        final Button cancel = (Button) v.findViewById(R.id.cancel_button);
        cancel.setOnClickListener(new OnClickListener() {
            
            @Override
            public void onClick(View v) {
                dismissDialog();
            }
        });
        

        this.algorithmSelector.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                nameView.setEnabled(true);
                keySizeView.setEnabled(true);
                confirm.setEnabled(true);
                expiryDateView.setEnabled(!isSymmetricAlgo((String) parent.getItemAtPosition(position)));
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                nameView.setEnabled(false);
                keySizeView.setEnabled(false);
                expiryDateView.setEnabled(false);
                confirm.setEnabled(false);
            }
        });

        return v;
    }

    protected void dismissDialog() {;
        dismiss();
    }

    private void showError(int errorId, int argId) {
        showError(errorId, mContext.getString(argId));
    }

    private void showError(int errorId, Object... args) {
        String msg = mContext.getString(errorId, args);
        this.errorView.setText(msg);
        this.errorView.setVisibility(View.VISIBLE);
    }
}
