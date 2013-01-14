
package com.android.keychain.manage;

import android.app.Activity;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.RemoteException;
import android.security.CryptOracle;
import android.security.IKeyChainService;
import android.security.KeyChain;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.android.keychain.R;

@SuppressWarnings("deprecation")
public class GrantKeyAccessActivity extends Activity {
    private abstract class GrantTask extends AsyncTask<Void, Void, Boolean> {
        private final boolean cancelActivityOnFail;
        
        public GrantTask(boolean cancelActivityOnFail) {
            this.cancelActivityOnFail = cancelActivityOnFail;
        }

        private final ProgressDialog pd = new ProgressDialog(GrantKeyAccessActivity.this);

        @Override
        protected Boolean doInBackground(Void... params) {
            KeyChain.KeyChainConnection connection = null;
            try {
                connection = KeyChain.bind(GrantKeyAccessActivity.this);
                return runOperation(connection.getService(), mSenderUid, mAlias);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                Log.e(TAG, "interrupted while doing grant stuff", ignored);
            } finally {
                if (connection != null)
                    connection.close();
            }

            return false;
        }

        protected abstract boolean runOperation(IKeyChainService service, int mSenderUid,
                String mAlias);

        @Override
        protected void onPostExecute(Boolean result) {
            pd.dismiss();

            if (result)
                finish(Activity.RESULT_OK);
            else if (cancelActivityOnFail)
                finish(Activity.RESULT_CANCELED);
        }

        @Override
        protected void onPreExecute() {
            pd.setIndeterminate(true);
            pd.setCancelable(false);
            pd.show();
        }
    }

    private static final String TAG = "GrantKeyAccess";
    private PendingIntent mSender;
    private int mSenderUid;
    private String mAlias;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.grant_access_dialog);

        Button b = (Button) findViewById(R.id.deny_button);
        b.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                finish(Activity.RESULT_CANCELED);
            }
        });

        b = (Button) findViewById(R.id.allow_button);
        b.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                grant();
            }
        });

    }

    private void checkGrant() {
        new GrantTask(false) {
            @Override
            protected boolean runOperation(IKeyChainService service, int mSenderUid, String mAlias) {
                try {
                    return service.hasGrant(mSenderUid, mAlias);
                } catch (RemoteException e) {
                    Log.e(TAG, "checking key access failed", e);
                    return false;
                }
            }
        }.execute();
    }

    protected void grant() {
        Log.d(TAG, "setting grant for " + mSenderUid + " to " + mAlias);

        new GrantTask(true) {
            @Override
            protected boolean runOperation(IKeyChainService service, int mSenderUid, String mAlias) {
                try {
                    service.setGrant(mSenderUid, mAlias, true);
                    return true;
                } catch (RemoteException e) {
                    Log.e(TAG, "checking key access failed", e);
                    return false;
                }
            }
        }.execute();
    }

    protected void finish(int result) {
        setResult(result);
        finish();
    }

    @Override
    protected void onResume() {
        super.onResume();

        mAlias = getIntent().getStringExtra(CryptOracle.EXTRA_ALIAS);
        mSender = getIntent().getParcelableExtra(KeyChain.EXTRA_SENDER);
        if (mSender == null) {
            // if no sender, bail, we need to identify the app to the user
            // securely.
            finish(Activity.RESULT_CANCELED);
            return;
        }
        try {
            mSenderUid = getPackageManager().getPackageInfo(
                    mSender.getIntentSender().getTargetPackage(), 0).applicationInfo.uid;
        } catch (PackageManager.NameNotFoundException e) {
            // if unable to find the sender package info bail,
            // we need to identify the app to the user securely.
            finish(Activity.RESULT_CANCELED);
            return;
        }

        checkGrant();

        TextView descView = (TextView) findViewById(R.id.grant_description);

        String pkg = mSender.getIntentSender().getTargetPackage();
        PackageManager pm = getPackageManager();
        CharSequence applicationLabel;
        try {
            applicationLabel = pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString();
        } catch (PackageManager.NameNotFoundException e) {
            applicationLabel = pkg;
        }

        descView.setText(getString(R.string.key_requesting_app, applicationLabel, mAlias));
    }
}
