
package com.android.keychain.manage;

import android.app.Activity;
import android.os.Bundle;

import com.android.keychain.R;

public class ManageContacts extends Activity {
    public static final String MIMETYPE = "vnd.android.cursor.item/key";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.manage_contacts);
        setTitle(R.string.manage_contacts);
    }
}
