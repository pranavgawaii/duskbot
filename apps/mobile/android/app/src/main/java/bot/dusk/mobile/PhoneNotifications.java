package bot.dusk.mobile;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.service.notification.StatusBarNotification;
import android.util.Base64;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.app.Person;
import androidx.core.content.pm.ShortcutInfoCompat;
import androidx.core.graphics.drawable.IconCompat;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;

/**
 * The conversation notifications the app draws itself from data-only dusk pushes: one MessagingStyle notification per
 * thread that stacks lines, a group summary once two or more are shown, the sealed preview opened with the phone's own
 * X25519 key, and the bot's cached avatar (or its letter).
 */
public final class PhoneNotifications {

    public static final String TAP_ACTION = "bot.dusk.mobile.NOTIFICATION_TAP";
    public static final String TAP_EXTRA = "dusk.tap";
    static final String GROUP = "dusk.messages";
    static final int MESSAGE_ID = 7101;
    static final int SUMMARY_ID = 7100;
    static final String READ_KIND = "read";
    private static final int KEEP_LINES = 6;
    private static final String EXTRA_IDS = "dusk.ids";
    private static final String EXTRA_COUNT = "dusk.count";
    private static final String EXTRA_BOT = "dusk.botName";
    private static final String KEY_FILE = "push-preview.key";
    private static final String SALT = "dusk-push-preview-v1";
    // DER prefix of an X.509 X25519 public key; the raw 32 bytes follow it
    private static final byte[] X25519_PREFIX = { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00 };

    static volatile boolean foreground;
    static volatile String viewing;

    private PhoneNotifications() {}

    public static boolean isDusk(Map<String, String> data) {
        return "1".equals(data.get("dusk")) && notEmpty(data.get("threadId"));
    }

    /** a data-only dusk push: append its line to its thread's notification, or post nothing while that chat is on screen;
     * a read takes the thread's notification away */
    public static synchronized void show(Context context, Map<String, String> data) {
        String threadId = data.get("threadId");
        if (READ_KIND.equals(data.get("kind"))) { clearRead(context, threadId, value(data, "id")); return; }
        if (foreground && threadId.equals(viewing)) return;
        NotificationChannels.ensure(context);
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null || !NotificationManagerCompat.from(context).areNotificationsEnabled()) return;
        String id = value(data, "id");
        String botId = value(data, "botId");
        String botName = notEmpty(data.get("botName")) ? data.get("botName") : context.getString(R.string.app_name);
        String body = open(context, data.get("sealed"));
        if (body == null) body = context.getString(R.string.notification_new_message);

        Notification current = active(manager, threadId);
        ArrayList<String> ids = new ArrayList<>();
        int count = 0;
        List<NotificationCompat.MessagingStyle.Message> earlier = new ArrayList<>();
        if (current != null) {
            ArrayList<String> seen = current.extras.getStringArrayList(EXTRA_IDS);
            if (seen != null) ids.addAll(seen);
            if (!id.isEmpty() && ids.contains(id)) return;
            count = current.extras.getInt(EXTRA_COUNT, 0);
            NotificationCompat.MessagingStyle old = NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(current);
            if (old != null) earlier = old.getMessages();
        }
        if (!id.isEmpty()) ids.add(id);
        while (ids.size() > 20) ids.remove(0);
        count++;

        IconCompat avatar = IconCompat.createWithBitmap(avatar(context, botId, botName));
        Person bot = new Person.Builder().setName(botName).setKey("bot:" + botId).setIcon(avatar).setImportant(true).build();
        Person you = new Person.Builder().setName(context.getString(R.string.notification_you)).build();
        NotificationCompat.MessagingStyle style = new NotificationCompat.MessagingStyle(you);
        for (int at = Math.max(0, earlier.size() - (KEEP_LINES - 1)); at < earlier.size(); at++) {
            NotificationCompat.MessagingStyle.Message line = earlier.get(at);
            style.addMessage(line.getText(), line.getTimestamp(), bot);
        }
        long now = System.currentTimeMillis();
        style.addMessage(body, now, bot);

        String tap = tapData(data).toString();
        Bundle extras = new Bundle();
        extras.putStringArrayList(EXTRA_IDS, ids);
        extras.putInt(EXTRA_COUNT, count);
        extras.putString(EXTRA_BOT, botName);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, NotificationChannels.MESSAGES)
            .setSmallIcon(R.drawable.ic_stat_duskbot)
            .setContentTitle(botName)
            .setContentText(body)
            .setStyle(style)
            .setNumber(count)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setWhen(now)
            .setShowWhen(true)
            .setGroup(GROUP)
            .setContentIntent(tapIntent(context, threadId, tap))
            .addExtras(extras);
        if (Build.VERSION.SDK_INT < 28) builder.setLargeIcon(avatar(context, botId, botName));
        String shortcut = conversationShortcut(context, threadId, botName, bot, avatar, tap);
        if (shortcut != null) builder.setShortcutId(shortcut);
        manager.notify(threadId, MESSAGE_ID, builder.build());
        summarize(context, manager);
        if (shortcut != null) offLauncher(context, shortcut);
    }

    /** the conversation was read on another device up to `id`: its notification goes unless a newer line came since */
    static void clearRead(Context context, String threadId, String id) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null) return;
        for (StatusBarNotification item : ours(manager)) {
            if (readClears(threadId, id, item.getTag(), latestId(item))) manager.cancel(item.getTag(), MESSAGE_ID);
        }
        summarize(context, manager);
    }

    static boolean readClears(String threadId, String id, String tag, String latest) {
        return notEmpty(id) && threadId.equals(tag) && id.equals(latest);
    }

    /** the group summary across conversations: shown while two or more are, quiet itself (the conversations alert) */
    static void summarize(Context context, NotificationManager manager) {
        List<StatusBarNotification> shown = ours(manager);
        if (shown.size() < 2) { manager.cancel(SUMMARY_ID); return; }
        NotificationCompat.InboxStyle inbox = new NotificationCompat.InboxStyle();
        int total = 0;
        for (StatusBarNotification item : shown) {
            Bundle extras = item.getNotification().extras;
            total += Math.max(1, extras.getInt(EXTRA_COUNT, 1));
            CharSequence text = extras.getCharSequence(Notification.EXTRA_TEXT);
            inbox.addLine(extras.getString(EXTRA_BOT, "") + (text == null ? "" : ": " + text));
        }
        String summary = context.getResources().getQuantityString(R.plurals.notification_summary, total, total);
        inbox.setSummaryText(summary);
        manager.notify(SUMMARY_ID, new NotificationCompat.Builder(context, NotificationChannels.MESSAGES)
            .setSmallIcon(R.drawable.ic_stat_duskbot)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(summary)
            .setStyle(inbox)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setGroup(GROUP)
            .setGroupSummary(true)
            .setGroupAlertBehavior(NotificationCompat.GROUP_ALERT_CHILDREN)
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .setContentIntent(PendingIntent.getActivity(context, SUMMARY_ID, new Intent(context, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT))
            .build());
    }

    /** the conversation notifications on screen (not the summary, not system-drawn pushes) */
    static List<StatusBarNotification> ours(NotificationManager manager) {
        List<StatusBarNotification> found = new ArrayList<>();
        for (StatusBarNotification item : manager.getActiveNotifications()) {
            Notification notification = item.getNotification();
            if (item.getId() != MESSAGE_ID || item.getTag() == null || notification == null) continue;
            if ((notification.flags & Notification.FLAG_GROUP_SUMMARY) != 0 || !GROUP.equals(notification.getGroup())) continue;
            found.add(item);
        }
        return found;
    }

    static String latestId(StatusBarNotification item) {
        ArrayList<String> ids = item.getNotification().extras.getStringArrayList(EXTRA_IDS);
        return ids == null || ids.isEmpty() ? null : ids.get(ids.size() - 1);
    }

    private static Notification active(NotificationManager manager, String threadId) {
        for (StatusBarNotification item : ours(manager)) if (threadId.equals(item.getTag())) return item.getNotification();
        return null;
    }

    private static JSONObject tapData(Map<String, String> data) {
        JSONObject dusk = new JSONObject();
        try {
            for (String key : new String[] { "kind", "botId", "threadId", "environmentId", "id", "groupId", "requestId" }) {
                if (notEmpty(data.get(key))) dusk.put(key, data.get(key));
            }
        } catch (org.json.JSONException ignored) {}
        return dusk;
    }

    private static Intent tapLaunch(Context context, String tap) {
        return new Intent(context, MainActivity.class).setAction(TAP_ACTION).putExtra(TAP_EXTRA, tap)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
    }

    private static PendingIntent tapIntent(Context context, String threadId, String tap) {
        return PendingIntent.getActivity(context, threadId.hashCode(), tapLaunch(context, tap), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    // a long-lived conversation shortcut puts the notification in the Conversations section with the bot's avatar.
    // Android 15 drops a dynamic shortcut excluded from the launcher, so it is pushed plainly and taken off the
    // launcher once the notification has cached it (a cached shortcut outlives its dynamic one).
    private static String conversationShortcut(Context context, String threadId, String botName, Person bot, IconCompat avatar, String tap) {
        if (Build.VERSION.SDK_INT < 30) return null;
        String id = "chat:" + threadId;
        try {
            context.getSystemService(ShortcutManager.class).pushDynamicShortcut(new ShortcutInfoCompat.Builder(context, id)
                .setShortLabel(botName)
                .setLongLived(true)
                .setPerson(bot)
                .setIcon(avatar)
                .setIntent(tapLaunch(context, tap))
                .setCategories(Collections.singleton("android.shortcut.conversation"))
                .build().toShortcutInfo());
            return id;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static void offLauncher(Context context, String id) {
        if (Build.VERSION.SDK_INT < 30) return;
        ShortcutManager shortcuts = context.getSystemService(ShortcutManager.class);
        try {
            for (int tries = 0; tries < 20; tries++) {
                for (ShortcutInfo info : shortcuts.getShortcuts(ShortcutManager.FLAG_MATCH_CACHED)) {
                    if (id.equals(info.getId())) { shortcuts.removeDynamicShortcuts(Collections.singletonList(id)); return; }
                }
                Thread.sleep(100);
            }
        } catch (InterruptedException | RuntimeException ignored) {}
    }

    // ---- avatars

    private static File avatarDir(Context context) {
        return new File(context.getFilesDir(), "notification-avatars");
    }

    private static File avatarFile(Context context, String botId) {
        return new File(avatarDir(context), botId.replaceAll("[^A-Za-z0-9_-]", "_") + ".png");
    }

    /** keeps the given bots' avatars (base64 png) and drops the rest */
    static void cacheAvatars(Context context, Map<String, String> pngs) {
        File dir = avatarDir(context);
        if (!dir.isDirectory() && !dir.mkdirs()) return;
        Set<String> keep = new java.util.HashSet<>();
        for (Map.Entry<String, String> entry : pngs.entrySet()) {
            File file = avatarFile(context, entry.getKey());
            keep.add(file.getName());
            try {
                byte[] bytes = Base64.decode(entry.getValue(), Base64.DEFAULT);
                if (bytes.length == 0 || bytes.length > 256 * 1024 || BitmapFactory.decodeByteArray(bytes, 0, bytes.length) == null) continue;
                File temp = new File(dir, file.getName() + ".tmp");
                try (FileOutputStream out = new FileOutputStream(temp)) { out.write(bytes); }
                if (!temp.renameTo(file)) temp.delete();
            } catch (Exception ignored) {}
        }
        File[] files = dir.listFiles();
        if (files != null) for (File file : files) if (!keep.contains(file.getName())) file.delete();
    }

    private static Bitmap avatar(Context context, String botId, String botName) {
        int size = Math.round(64 * context.getResources().getDisplayMetrics().density);
        Bitmap cached = botId.isEmpty() ? null : BitmapFactory.decodeFile(avatarFile(context, botId).getPath());
        Bitmap out = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(out);
        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);
        if (cached != null) {
            canvas.drawOval(new RectF(0, 0, size, size), paint);
            paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.SRC_IN));
            int side = Math.min(cached.getWidth(), cached.getHeight());
            Rect from = new Rect((cached.getWidth() - side) / 2, (cached.getHeight() - side) / 2, (cached.getWidth() + side) / 2, (cached.getHeight() + side) / 2);
            canvas.drawBitmap(cached, from, new Rect(0, 0, size, size), paint);
            return out;
        }
        // neutral tonal circle with the bot's first letter
        paint.setColor(0xFF6E6B68);
        canvas.drawOval(new RectF(0, 0, size, size), paint);
        String letter = botName.trim().isEmpty() ? "d" : new String(Character.toChars(botName.trim().codePointAt(0))).toUpperCase(Locale.getDefault());
        paint.setColor(0xFFF6F5F3);
        paint.setTextAlign(Paint.Align.CENTER);
        paint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        paint.setTextSize(size * 0.44f);
        Paint.FontMetrics metrics = paint.getFontMetrics();
        canvas.drawText(letter, size / 2f, size / 2f - (metrics.ascent + metrics.descent) / 2f, paint);
        return out;
    }

    // ---- sealed previews

    /** the phone's preview public key (raw X25519, base64url), made once; null below Android 12 */
    static synchronized String previewKey(Context context) {
        KeyPair pair = keyPair(context, true);
        if (pair == null) return null;
        byte[] encoded = pair.getPublic().getEncoded();
        return Base64.encodeToString(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length), Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static KeyPair keyPair(Context context, boolean create) {
        if (Build.VERSION.SDK_INT < 31) return null;
        // noBackupFilesDir: app-private, never in a backup or a device transfer
        File file = new File(context.getNoBackupFilesDir(), KEY_FILE);
        try {
            KeyFactory factory = KeyFactory.getInstance("XDH");
            if (file.isFile()) {
                byte[] stored = Base64.decode(new String(java.nio.file.Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8), Base64.NO_WRAP);
                PrivateKey priv = factory.generatePrivate(new PKCS8EncodedKeySpec(Arrays.copyOfRange(stored, 32, stored.length)));
                PublicKey pub = factory.generatePublic(new X509EncodedKeySpec(concat(X25519_PREFIX, Arrays.copyOfRange(stored, 0, 32))));
                return new KeyPair(pub, priv);
            }
            if (!create) return null;
            // Conscrypt's XDH generator makes X25519 keys and takes no parameter spec
            KeyPair pair = KeyPairGenerator.getInstance("XDH").generateKeyPair();
            byte[] pub = pair.getPublic().getEncoded();
            byte[] stored = concat(Arrays.copyOfRange(pub, pub.length - 32, pub.length), pair.getPrivate().getEncoded());
            File temp = new File(file.getPath() + ".tmp");
            try (FileOutputStream out = new FileOutputStream(temp)) { out.write(Base64.encode(stored, Base64.NO_WRAP)); }
            if (!temp.renameTo(file)) return null;
            return pair;
        } catch (Exception ignored) {
            return null;
        }
    }

    /** sealed = base64url(ephemeral public 32 | iv 12 | AES-256-GCM ciphertext | tag 16); null when it cannot be opened */
    static String open(Context context, String sealed) {
        if (!notEmpty(sealed)) return null;
        try {
            KeyPair pair = keyPair(context, false);
            if (pair == null) return null;
            byte[] box = Base64.decode(sealed, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
            if (box.length < 32 + 12 + 16) return null;
            PublicKey ephemeral = KeyFactory.getInstance("XDH").generatePublic(new X509EncodedKeySpec(concat(X25519_PREFIX, Arrays.copyOfRange(box, 0, 32))));
            KeyAgreement agreement = KeyAgreement.getInstance("XDH");
            agreement.init(pair.getPrivate());
            agreement.doPhase(ephemeral, true);
            byte[] key = hkdf(agreement.generateSecret(), SALT.getBytes(StandardCharsets.UTF_8), "seal".getBytes(StandardCharsets.UTF_8));
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, box, 32, 12));
            String text = new String(cipher.doFinal(box, 44, box.length - 44), StandardCharsets.UTF_8).trim();
            if (text.isEmpty()) return null;
            return text.length() > 240 ? text.substring(0, 240) : text;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 1);
        return Arrays.copyOf(mac.doFinal(), 32);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String value(Map<String, String> data, String key) {
        String value = data.get(key);
        return value == null ? "" : value;
    }

    private static boolean notEmpty(String value) {
        return value != null && !value.isEmpty();
    }
}
