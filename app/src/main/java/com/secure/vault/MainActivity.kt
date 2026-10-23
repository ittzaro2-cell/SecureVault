package com.secure.vault

import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

private enum class AuthMode(val label: String) { PIN("PIN"), PATTERN("شێوە"), PASSWORD("وشەی نهێنی") }
private data class VaultItem(val name: String, val size: Long)

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(8192, 8192) // FLAG_SECURE: block screenshots and recents thumbnails
        setContent { MaterialTheme { SecureVaultApp() } }
    }
}

@Composable
private fun SecureVaultApp() {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("vault_auth", Context.MODE_PRIVATE) }
    var mode by remember { mutableStateOf(runCatching { AuthMode.valueOf(prefs.getString("mode", "PIN")!!) }.getOrDefault(AuthMode.PIN)) }
    var configured by remember { mutableStateOf(prefs.contains("credential_hash")) }
    var unlocked by remember { mutableStateOf(false) }
    var biometricEnabled by remember { mutableStateOf(prefs.getBoolean("biometric", false)) }
    var message by remember { mutableStateOf("") }
    var refresh by remember { mutableIntStateOf(0) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        var copied = 0
        uris.forEach { uri ->
            try {
                val rawName = queryDisplayName(context, uri) ?: "media_${System.currentTimeMillis()}"
                val safeName = rawName.substringAfterLast('/').replace(Regex("[^A-Za-z0-9._-]"), "_").take(100)
                val destination = File(vaultDir(context), "${System.currentTimeMillis()}_$safeName")
                context.contentResolver.openInputStream(uri)?.use { input -> destination.outputStream().use { output -> input.copyTo(output) } }
                copied++
            } catch (_: Exception) { }
        }
        if (copied > 0) { message = "$copied فایل خرایە ناو گەنجینە"; refresh++ }
        else if (uris.isNotEmpty()) message = "نەتوانرا فایلەکان کۆپی بکرێن"
    }

    if (!unlocked) {
        LoginScreen(
            mode = mode, onMode = { mode = it }, configured = configured, message = message,
            onSubmit = { secret ->
                if (secret.isBlank()) message = "تکایە زانیارییەکە بنووسە"
                else if (!configured) {
                    if (mode == AuthMode.PIN && secret.length < 4) message = "PIN دەبێت لانیکەم ٤ ژمارە بێت"
                    else if (mode == AuthMode.PATTERN && secret.split(',').distinct().size < 4) message = "شێوەکە لانیکەم ٤ خاڵی جیاواز بەکاربهێنێت"
                    else if (mode == AuthMode.PASSWORD && secret.length < 8) message = "وشەی نهێنی دەبێت لانیکەم ٨ پیت بێت"
                    else {
                        val (salt, hash) = makeHash(secret)
                        prefs.edit().putString("mode", mode.name).putString("salt", salt).putString("credential_hash", hash).apply()
                        configured = true; unlocked = true; message = ""
                    }
                } else {
                    val valid = prefs.getString("mode", "PIN") == mode.name && verifyHash(secret, prefs.getString("salt", "")!!, prefs.getString("credential_hash", "")!!)
                    if (valid) { unlocked = true; message = "" } else message = "زانیاریی چوونەژوورەوە هەڵەیە"
                }
            },
            onBiometric = { launchBiometric(context) { ok -> if (ok) { unlocked = true; message = "" } else message = "ناسینەوەی پەنجەمۆر سەرکەوتوو نەبوو" } },
            showBiometric = configured && biometricEnabled && biometricAvailable(context)
        )
    } else {
        VaultScreen(
            message = message,
            items = remember(refresh) { vaultDir(context).listFiles()?.filter { it.isFile }?.sortedByDescending { it.lastModified() }?.map { VaultItem(it.name, it.length()) } ?: emptyList() },
            onPick = { picker.launch(arrayOf("image/*", "video/*")) },
            biometricEnabled = biometricEnabled,
            onBiometricToggle = { value -> biometricEnabled = value; prefs.edit().putBoolean("biometric", value).apply(); message = if (value) "پەنجەمۆر چالاک کرا؛ دەتوانیت لە شاشەی چوونەژوورەوە بەکاریبهێنیت" else "پەنجەمۆر ناچالاک کرا" },
            onDelete = { name -> File(vaultDir(context), name).delete(); refresh++; message = "فایلەکە سڕایەوە" },
            onLock = { unlocked = false; message = "" }
        )
    }
}

@Composable
private fun LoginScreen(mode: AuthMode, onMode: (AuthMode) -> Unit, configured: Boolean, message: String, onSubmit: (String) -> Unit, onBiometric: () -> Unit, showBiometric: Boolean) {
    var text by remember(mode) { mutableStateOf("") }
    var pattern by remember(mode) { mutableStateOf(emptyList<Int>()) }
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
        Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
            Text("SecureVault", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp)); Text(if (configured) "بۆ کردنەوەی گەنجینەکە بچۆ ژوورەوە" else "شێوازی قفڵ دیاری بکە و زانیارییەکەت دابنێ")
            Spacer(Modifier.height(24.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { AuthMode.entries.forEach { item -> FilterChip(selected = mode == item, onClick = { onMode(item); text = ""; pattern = emptyList() }, label = { Text(item.label) }) } }
            Spacer(Modifier.height(18.dp))
            if (mode == AuthMode.PATTERN) {
                Text(if (pattern.isEmpty()) "بە ڕیز خاڵەکان هەڵبژێرە" else "${pattern.size} خاڵ")
                Spacer(Modifier.height(12.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) { (0..2).forEach { row -> Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) { (0..2).forEach { col -> val index = row * 3 + col; Surface(shape = CircleShape, color = if (index in pattern) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.size(62.dp).clickable { if (index !in pattern) pattern = pattern + index }) { Box(contentAlignment = Alignment.Center) { Text("●", color = MaterialTheme.colorScheme.onSecondaryContainer) } } } } } }
                TextButton(onClick = { pattern = emptyList() }) { Text("پاککردنەوە") }
            } else {
                OutlinedTextField(value = text, onValueChange = { text = it }, label = { Text(mode.label) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = if (mode == AuthMode.PIN) KeyboardType.NumberPassword else KeyboardType.Password), modifier = Modifier.fillMaxWidth())
            }
            Spacer(Modifier.height(16.dp))
            Button(onClick = { onSubmit(if (mode == AuthMode.PATTERN) pattern.joinToString(",") else text) }, modifier = Modifier.fillMaxWidth()) { Text(if (configured) "کردنەوە" else "دروستکردنی قفڵ") }
            if (showBiometric) { Spacer(Modifier.height(8.dp)); OutlinedButton(onClick = onBiometric, modifier = Modifier.fillMaxWidth()) { Text("🔒 چوونەژوورەوە بە پەنجەمۆر") } }
            if (message.isNotBlank()) { Spacer(Modifier.height(12.dp)); Text(message, color = MaterialTheme.colorScheme.error) }
        }
    }
}

@Composable
private fun VaultScreen(message: String, items: List<VaultItem>, onPick: () -> Unit, biometricEnabled: Boolean, onBiometricToggle: (Boolean) -> Unit, onDelete: (String) -> Unit, onLock: () -> Unit) {
    var expandedItem by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Column { Text("گەنجینە", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold); Text("${items.size} فایل لە شوێنی تایبەتی ئەپ") }
            TextButton(onClick = onLock) { Text("قفڵکردن") }
        }
        Spacer(Modifier.height(16.dp))
        Button(onClick = onPick, modifier = Modifier.fillMaxWidth()) { Text("+ زیادکردنی وێنە / ڤیدیۆ") }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) { Switch(checked = biometricEnabled, onCheckedChange = onBiometricToggle); Spacer(Modifier.width(8.dp)); Text("ڕێگەدان بە چوونەژوورەوەی پەنجەمۆر") }
        if (message.isNotBlank()) Text(message, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall)
        HorizontalDivider(Modifier.padding(vertical = 12.dp))
        if (items.isEmpty()) Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text("هێشتا هیچ فایلێک زیاد نەکراوە") }
        else LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) { items(items, key = { it.name }) { item ->
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp), border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)) {
                Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("▣", style = MaterialTheme.typography.headlineSmall); Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) { Text(item.name.substringAfter('_'), fontWeight = FontWeight.Medium); Text(formatSize(item.size), style = MaterialTheme.typography.bodySmall) }
                    TextButton(onClick = { expandedItem = item.name }) { Text("سڕینەوە") }
                    if (expandedItem == item.name) AlertDialog(onDismissRequest = { expandedItem = null }, title = { Text("سڕینەوەی فایل؟") }, text = { Text(item.name) }, confirmButton = { TextButton(onClick = { onDelete(item.name); expandedItem = null }) { Text("سڕینەوە") } }, dismissButton = { TextButton(onClick = { expandedItem = null }) { Text("پاشگەزبوونەوە") } })
                }
            }
        } }
    }
}

private fun vaultDir(context: Context): File = File(context.filesDir, "vault").apply { if (!exists()) mkdirs() }
private fun queryDisplayName(context: Context, uri: android.net.Uri): String? = context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
private fun makeHash(secret: String): Pair<String, String> {
    val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
    val spec = PBEKeySpec(secret.toCharArray(), salt, 120_000, 256)
    val hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    return salt.toHex() to hash.toHex()
}
private fun verifyHash(secret: String, saltHex: String, expectedHex: String): Boolean = try {
    val salt = saltHex.hexToBytes(); val spec = PBEKeySpec(secret.toCharArray(), salt, 120_000, 256)
    MessageDigest.isEqual(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded, expectedHex.hexToBytes())
} catch (_: Exception) { false }
private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
private fun String.hexToBytes() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun formatSize(size: Long) = if (size < 1024 * 1024) "${size / 1024} KB" else "%.1f MB".format(size / (1024.0 * 1024.0))

private fun biometricAvailable(context: Context): Boolean = Build.VERSION.SDK_INT >= 28 && androidx.biometric.BiometricManager.from(context).canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
private fun launchBiometric(context: Context, result: (Boolean) -> Unit) {
    if (context !is FragmentActivity || Build.VERSION.SDK_INT < 28) { result(false); return }
    val prompt = BiometricPrompt(context, ContextCompat.getMainExecutor(context), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) { result(true) }
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { result(false) }
        override fun onAuthenticationFailed() { }
    })
    prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("کردنەوەی SecureVault").setSubtitle("پەنجەمۆر بەکاربهێنە").setNegativeButtonText("پاشگەزبوونەوە").build())
}
