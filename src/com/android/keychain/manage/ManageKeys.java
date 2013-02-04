package com.android.keychain.manage;

import android.app.Activity;
import android.app.FragmentTransaction;
import android.os.Bundle;

import com.android.keychain.R;

public class ManageKeys extends Activity {
    private KeysListFragment mFragment;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.manage_keys);
        setTitle(R.string.manage_keys);
        
        FragmentTransaction ft = getFragmentManager().beginTransaction();
        mFragment = new KeysListFragment();
        ft.add(R.id.keySelectListFrame, mFragment, "keyselectlist");
        ft.commit();
    }
}
