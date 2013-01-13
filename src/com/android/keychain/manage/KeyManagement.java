
package com.android.keychain.manage;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Toast;

import com.android.keychain.R;

public class KeyManagement extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.manage_main);
    }
    
    public void openContacts(View view) {
        Intent intent = new Intent(this, ManageContacts.class);
        startActivity(intent);
    }
    
    public void openKeys(View view) {
        Toast.makeText(this, "not yet implemented", Toast.LENGTH_SHORT).show();
    }
}
