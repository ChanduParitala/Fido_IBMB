package com.client_fido2

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.facebook.react.bridge.*
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import android.util.Base64
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

class SecureKeyModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String {
        return "SecureKeyModule"
    }

    @ReactMethod
    fun authenticateUser(promise: Promise) {
        try {
            val activity = reactApplicationContext.currentActivity as? FragmentActivity
                ?: throw Exception("Activity is not available")

            val executor = ContextCompat.getMainExecutor(activity)
            val biometricPrompt = BiometricPrompt(activity, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        promise.resolve(true) // Return success to React Native
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        promise.reject("AUTH_ERROR", errString.toString())
                    }

                    override fun onAuthenticationFailed() {
                        promise.reject("AUTH_FAILED", "Biometric authentication failed")
                    }
                })

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate to sign data")
                .setSubtitle("Biometric authentication is required")
                .setNegativeButtonText("Cancel")
                .build()

            biometricPrompt.authenticate(promptInfo)
        } catch (e: Exception) {
            promise.reject("AUTH_EXCEPTION", "Error during authentication", e)
        }
    }

    @ReactMethod
    fun generateKeyPair(alias: String, promise: Promise) {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1) // Force authentication per operation
                .setUserAuthenticationValidWhileOnBody(false)
                .setUnlockedDeviceRequired(true) // Ensure device is unlocked
                .setIsStrongBoxBacked(true) // Use StrongBox if supported
                .setInvalidatedByBiometricEnrollment(true)
                .build()

            keyPairGenerator.initialize(keyGenParameterSpec)
            val keyPair = keyPairGenerator.generateKeyPair()

            val publicKeyBytes = keyPair.public.encoded
            val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)

            promise.resolve(publicKeyBase64)
        } catch (e: Exception) {
            promise.reject("KEY_GEN_ERROR", "Failed to generate key pair", e)
        }
    }

    @ReactMethod
    fun signData(alias: String, data: String, promise: Promise) {
        val activity = reactApplicationContext.currentActivity as? FragmentActivity
            ?: throw Exception("Activity is not available")

        activity.runOnUiThread {
            try {
                val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                val privateKey = keyStore.getKey(alias, null) as? java.security.PrivateKey
                    ?: throw Exception("Private key not found for alias: $alias")

                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                println("signing initiated with private key $privateKey")

                val cryptoObject = BiometricPrompt.CryptoObject(signature)
                val executor = ContextCompat.getMainExecutor(activity)
                val biometricPrompt = BiometricPrompt(activity, executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            try {
                                val authenticatedSignature = result.cryptoObject?.signature
                                    ?: throw Exception("CryptoObject is null")

                                val decodedData = Base64.decode(data, Base64.DEFAULT)
                                authenticatedSignature.update(decodedData)
                                println("data updated.. $decodedData")

                                val signedData = authenticatedSignature.sign()
                                println("data signed.. $signedData")
                                val signedBase64 = Base64.encodeToString(signedData, Base64.NO_WRAP)

                                promise.resolve(signedBase64)
                            } catch (e: Exception) {
                                println("error signing data.. ${e.message}")
                                promise.reject("SIGN_ERROR", "Failed to sign data", e)
                            }
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            promise.reject("AUTH_ERROR", errString.toString())
                        }

                        override fun onAuthenticationFailed() {
                            promise.reject("AUTH_FAILED", "Biometric authentication failed")
                        }
                    })

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Authenticate to sign data")
                    .setSubtitle("Biometric authentication is required")
                    .setNegativeButtonText("Cancel")
                    .build()

                // Authenticate using CryptoObject to link biometric auth with signing operation
                biometricPrompt.authenticate(promptInfo, cryptoObject)

            } catch (e: Exception) {
                promise.reject("SIGN_INIT_ERROR", "Failed to initialize signing", e)
            }
        }
    }
}
