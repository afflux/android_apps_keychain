
package com.android.keychain.manage;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.security.Credentials;
import android.security.KeyStore;
import android.view.View;
import android.widget.Toast;

import com.android.keychain.R;

public class KeyManagement extends Activity {

    private static String KEY_STATE = "state";

    private static final int REQUEST_UNLOCK = 1;

    private static enum State {
        INITIAL, UNLOCK_REQUESTED
    };

    private State mState;

    // beware that some of these KeyStore operations such as saw and
    // get do file I/O in the remote keystore process and while they
    // do not cause StrictMode violations, they logically should not
    // be done on the UI thread.
    private KeyStore mKeyStore = KeyStore.getInstance();

    // the KeyStore.state operation is safe to do on the UI thread, it
    // does not do a file operation.
    private boolean isKeyStoreUnlocked() {
        return mKeyStore.state() == KeyStore.State.UNLOCKED;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (savedInstanceState == null) {
            mState = State.INITIAL;
        } else {
            mState = (State) savedInstanceState.getSerializable(KEY_STATE);
            if (mState == null) {
                mState = State.INITIAL;
            }
        }
    }

    public void openContacts(View view) {
        Intent intent = new Intent(this, ManageContacts.class);
        startActivity(intent);
    }

    public void openKeys(View view) {
        Toast.makeText(this, "not yet implemented", Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onResume() {
        super.onResume();

        // see if KeyStore has been unlocked, if not start activity to do so
        switch (mState) {
            case INITIAL:
                if (!isKeyStoreUnlocked()) {
                    mState = State.UNLOCK_REQUESTED;
                    this.startActivityForResult(new Intent(Credentials.UNLOCK_ACTION),
                            REQUEST_UNLOCK);
                    // Note that Credentials.unlock will start an
                    // Activity and we will be paused but then resumed
                    // when the unlock Activity completes and our
                    // onActivityResult is called with REQUEST_UNLOCK
                    return;
                }

                setContentView(R.layout.manage_main);
                return;
            case UNLOCK_REQUESTED:
                // we've already asked, but have not heard back, probably just
                // rotated.
                // wait to hear back via onActivityResult
                return;
            default:
                throw new AssertionError();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
            case REQUEST_UNLOCK:
                if (isKeyStoreUnlocked()) {
                    setContentView(R.layout.manage_main);
                } else {
                    // user must have canceled unlock, give up
                    finish();
                }
                return;
            default:
                throw new AssertionError();
        }
    }
}
