package com.ahm.capacitor.biometric;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.getcapacitor.JSObject;
import com.getcapacitor.NativePlugin;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.Executors;
import android.content.pm.PackageManager;
import android.util.Base64;
import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@NativePlugin()
public class BiometricAuth extends Plugin {
    static String KEY_NAME = "biometricauthcapacitor";
    static String PREF_KEY_NAME = "encryptedCode";
    static String PREF_IV = "iv";
    private CancellationSignal cancellationSignal;

    @PluginMethod()
    public void isAvailable(PluginCall call) {
        JSObject ret = new JSObject();


        ret.put("has", isBiometryAvailable());
        call.resolve(ret);
    }

    @PluginMethod()
    public void verify(PluginCall call) {
        displayBiometricPrompt(call);
    }

    @PluginMethod()
    @TargetApi(Build.VERSION_CODES.P)
    public void store(final PluginCall call) {
        final String code = call.getString("code");

        Context context = getContext();

        this.doGetKey();

        try {
            Cipher cipher = getCipher();

            SecretKey secretKey = getSecretKey();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            this.storeIv(cipher.getIV());

            android.hardware.biometrics.BiometricPrompt biometricPrompt = new android.hardware.biometrics.BiometricPrompt.Builder(context)
                    .setTitle(call.getString("title", "Biometric"))
                    .setSubtitle(call.getString("subTitle", "Authentication is required to continue"))
                    .setDescription(call.getString("description", "This app uses biometric authentication to protect your data."))
                    .setNegativeButton(call.getString("cancel", "Cancel"), context.getMainExecutor(), new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialogInterface, int i) {
                            call.reject("failed");
                        }
                    })
                    .build();
            biometricPrompt.authenticate(new android.hardware.biometrics.BiometricPrompt.CryptoObject(cipher), getCancellationSignal(call), context.getMainExecutor(), new android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode,
                                                  CharSequence errString) {

                    super.onAuthenticationError(errorCode, errString);
                    call.reject("failed");
                }

                @Override
                public void onAuthenticationHelp(int helpCode,
                                                 CharSequence helpString) {
                    super.onAuthenticationHelp(helpCode, helpString);
                    call.reject("failed");
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    call.reject("failed");
                }

                @Override
                public void onAuthenticationSucceeded(android.hardware.biometrics.BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);

                    try {
                        byte[] encryptedInfo = result.getCryptoObject().getCipher().doFinal(
                                code.getBytes(Charset.defaultCharset()));

                        SharedPreferences sharedPref = getSharedPreferences();
                        sharedPref.edit().putString(PREF_KEY_NAME, Base64.encodeToString(encryptedInfo, Base64.DEFAULT)).apply();
                        call.resolve();
                    } catch (Exception e) {
                        call.reject("unable to encrypt");
                    }
                }
            });
        } catch (Exception e) {
            call.reject("failed store");
        }

        call.resolve();
    }

    @TargetApi(Build.VERSION_CODES.P)
    private void displayBiometricPrompt(final PluginCall call) {
        if (Build.VERSION.SDK_INT < 28) {
            call.reject("failed");
            return;
        }

        try {
            Context context = getContext();
            Cipher cipher = getCipher();
            SecretKey secretKey = getSecretKey();

            IvParameterSpec ivParameterSpec = new IvParameterSpec(this.getIv());

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            android.hardware.biometrics.BiometricPrompt biometricPrompt = new android.hardware.biometrics.BiometricPrompt.Builder(context)
                    .setTitle(call.getString("title", "Biometric"))
                    .setSubtitle(call.getString("subTitle", "Authentication is required to continue"))
                    .setDescription(call.getString("description", "This app uses biometric authentication to protect your data."))
                    .setNegativeButton(call.getString("cancel", "Cancel"), context.getMainExecutor(), new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialogInterface, int i) {
                            call.reject("failed");
                        }
                    })
                    .build();
            biometricPrompt.authenticate(new android.hardware.biometrics.BiometricPrompt.CryptoObject(cipher), getCancellationSignal(call), context.getMainExecutor(), getAuthenticationCallback(call));
        } catch (Exception e) {
            call.reject("failed verify");
        }
    }

    private boolean isBiometryAvailable() {
        if (Build.VERSION.SDK_INT < 28) {
            return false;
        }

        Context context = getContext();
        if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            return true;
        }

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (Exception e) {
            return false;
        }

        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException |
                NoSuchProviderException e) {
            return false;
        }

        if (keyGenerator == null || keyStore == null) {
            return false;
        }

        try {
            keyStore.load(null);
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder("dummy_key",
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            return false;
        }
        return true;

    }

    @TargetApi(Build.VERSION_CODES.P)
    private android.hardware.biometrics.BiometricPrompt.AuthenticationCallback getAuthenticationCallback(final PluginCall call) {
        return new android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              CharSequence errString) {

                super.onAuthenticationError(errorCode, errString);
                call.reject("failed");
            }

            @Override
            public void onAuthenticationHelp(int helpCode,
                                             CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
                call.reject("failed");
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                call.reject("failed");
            }

            @Override
            public void onAuthenticationSucceeded(android.hardware.biometrics.BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);

                SharedPreferences sharedPref = getSharedPreferences();
                String storedCode = sharedPref.getString(PREF_KEY_NAME, null);

                if (storedCode == null) {
                    call.resolve();
                    return;
                }

                byte[] encryptedInfo = Base64.decode(storedCode, Base64.DEFAULT);

                try {
                    byte[] decryptedInfo = result.getCryptoObject().getCipher().doFinal(encryptedInfo);

                    JSObject ret = new JSObject();
                    ret.put("verified", true);
                    ret.put("code", new String(decryptedInfo, Charset.defaultCharset()));
                    call.resolve(ret);
                } catch (Exception e) {
                    call.reject("failed to decrypt");
                }
            }
        };
    }

    private CancellationSignal getCancellationSignal(final PluginCall call) {

        cancellationSignal = new CancellationSignal();
        cancellationSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            @Override
            public void onCancel() {
                call.reject("failed");
            }
        });

        return cancellationSignal;
    }

    private void generateSecretKey(KeyGenParameterSpec keyGenParameterSpec) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();
        } catch (Exception e) {
            return;
        }
    }

    private SecretKey getSecretKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

            // Before the keystore can be accessed, it must be loaded.
            keyStore.load(null);
            return ((SecretKey) keyStore.getKey(KEY_NAME, null));
        } catch (Exception e) {
            return null;
        }
    }

    private Cipher getCipher() {
        try {
            return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (Exception e) {
            return null;
        }
    }

    public void doGetKey() {
        generateSecretKey(new KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .build());

    }

    public SharedPreferences getSharedPreferences() {
        return this.getContext().getSharedPreferences("biometricauthcapacitor", Context.MODE_PRIVATE);
    }

    public void storeIv(byte[] iv) {
        SharedPreferences sharedPref = getSharedPreferences();
        sharedPref.edit().putString(PREF_IV, Base64.encodeToString(iv, Base64.DEFAULT)).apply();
    }

    public byte[] getIv() {
        SharedPreferences sharedPref = getSharedPreferences();
        String b = sharedPref.getString(PREF_IV, "");

        return Base64.decode(b, Base64.DEFAULT);
    }
}
