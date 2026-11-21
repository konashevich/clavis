package clavis.holder;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_consent);
        TextView profile = findViewById(R.id.profile);
        try {
            byte[] buffer = new byte[128];
            int count = Core.profile(buffer);
            if (count < 0) {
                profile.setText(R.string.core_silent);
            } else {
                profile.setText(new String(buffer, 0, count, StandardCharsets.UTF_8));
            }
        } catch (Throwable error) {
            profile.setText(R.string.core_missing);
        }
    }
}
