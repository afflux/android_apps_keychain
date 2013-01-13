
package com.android.keychain.manage;

import android.app.Activity;
import android.app.DialogFragment;
import android.os.Bundle;
import android.view.View;

import com.android.keychain.R;

public class ContactDetails extends Activity {
    public static final String CONTACT_KEY = "contact_key";
    public static final String CONTACT_DISPLAY_NAME = "display_name";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.contact_details);
        
        setTitle(getIntent().getStringExtra(CONTACT_DISPLAY_NAME));
    }
    
    public void addKey(View view) {
        DialogFragment dialog = new KeySelectDialogFragment();
        dialog.show(getFragmentManager(), "select");
    }
}
