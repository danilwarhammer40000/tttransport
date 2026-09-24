package com.tt.transport

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/**
 * Split-tunnel app picker: checkbox list of installed launchable apps.
 * Selection is persisted via AppSelectionStore and read by
 * TunnelService when building the VPN (addAllowedApplication
 * for each selected package -- see that class for why an empty
 * selection means "tunnel everything" rather than "tunnel nothing").
 */
class AppSelectionActivity : AppCompatActivity() {

    private lateinit var apps: List<AppSelectionStore.AppEntry>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_selection)

        apps = AppSelectionStore.listSelectableApps(applicationContext)
        val selected = AppSelectionStore.getSelectedPackages(applicationContext)

        val listView = findViewById<ListView>(R.id.appListView)
        val adapter = ArrayAdapter(
            this,
            android.R.layout.simple_list_item_multiple_choice,
            apps.map { "${it.label}\n${it.packageName}" }
        )
        listView.adapter = adapter

        apps.forEachIndexed { index, app ->
            if (selected.contains(app.packageName)) {
                listView.setItemChecked(index, true)
            }
        }

        findViewById<Button>(R.id.btnSaveSelection).setOnClickListener {
            val checked = listView.checkedItemPositions
            val newSelection = mutableSetOf<String>()
            for (i in 0 until apps.size) {
                if (checked.get(i)) {
                    newSelection.add(apps[i].packageName)
                }
            }
            AppSelectionStore.setSelectedPackages(applicationContext, newSelection)
            Toast.makeText(
                this,
                "Saved: ${newSelection.size} app(s) selected for tunneling",
                Toast.LENGTH_SHORT
            ).show()
            finish()
        }
    }
}
