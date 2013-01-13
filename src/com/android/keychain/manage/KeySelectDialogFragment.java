
package com.android.keychain.manage;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.ListView;
import android.widget.SimpleAdapter;
import android.widget.TextView;
import android.widget.Toast;

import com.android.keychain.R;

import java.util.ArrayList;
import java.util.Map;

public class KeySelectDialogFragment extends DialogFragment {
    public KeySelectDialogFragment() {
    }

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());

        LayoutInflater inflater = getActivity().getLayoutInflater();

        TextView contextView = (TextView) inflater.inflate(R.layout.cert_chooser_header, null);

        contextView.setText(R.string.key_select_description);
        View footer = inflater.inflate(R.layout.cert_chooser_footer, null);

        final ListView lv = (ListView) inflater.inflate(R.layout.cert_chooser, null);
        lv.addHeaderView(contextView, null, false);
        lv.addFooterView(footer, null, false);

        lv.setOnItemClickListener(new AdapterView.OnItemClickListener() {

            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                lv.setItemChecked(position, true);
            }
        });

        lv.setAdapter(new SimpleAdapter(getActivity(), new ArrayList<Map<String, ?>>(),
                android.R.layout.simple_list_item_1, new String[] {
                    "ass"
                }, new int[] {
                    android.R.id.text1
                }));

        builder.setView(lv);

        builder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int id) {
                dialog.cancel(); // will cause OnDismissListener to be called
            }
        });

        boolean empty = true; // TODO implement adapter
                              // (adapter.mAliases.isEmpty());

        if (!empty) {
            builder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {

                @Override
                public void onClick(DialogInterface dialog, int which) {
                    Toast.makeText(getActivity(), "not yet implemented", Toast.LENGTH_SHORT).show();
                    dialog.cancel();
                }
            });
        }

        builder.setTitle(R.string.key_select);

        final Dialog dialog = builder.create();

        Button installButton = (Button) footer.findViewById(R.id.cert_chooser_install_button);
        installButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast.makeText(getActivity(), "not yet implemented", Toast.LENGTH_SHORT).show();
                dialog.dismiss();
            }
        });

        Button generateButton = (Button) footer.findViewById(R.id.cert_chooser_generate_button);
        generateButton.setVisibility(View.VISIBLE);
        generateButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast.makeText(getActivity(), "not yet implemented", Toast.LENGTH_SHORT).show();
                dialog.dismiss();
            }
        });

        return dialog;
    }
}
