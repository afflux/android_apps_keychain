
package com.android.keychain.manage;

import android.app.Activity;
import android.app.FragmentTransaction;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import com.android.keychain.R;

public class KeySelectListActivity extends Activity {
    private KeysListFragment mFragment;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.key_chooser);

        FragmentTransaction ft = getFragmentManager().beginTransaction();
        mFragment = new KeysListFragment();
        ft.add(R.id.keySelectListFrame, mFragment, "keyselectlist");
        ft.commit();

        TextView contextView = (TextView) findViewById(R.id.cert_chooser_header);
        contextView.setText(R.string.key_select_description);
    }

    protected void finish(String alias) {
        if (alias == null)
            setResult(Activity.RESULT_CANCELED);
        else {
            Intent data = new Intent();
            data.putExtra("alias", alias);
            setResult(Activity.RESULT_OK, data);
        }
        finish();
    }

    public void cancelClicked(View v) {
        finish(null);
    }

    public void selectClicked(View v) {
        String alias = mFragment.getSelectedAlias();
        finish(alias);
    }
}
