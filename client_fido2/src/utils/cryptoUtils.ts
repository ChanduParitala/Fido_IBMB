import { NativeModules } from 'react-native';
import { base64ToBase64Url } from './fido2Utils';

const { SecureKeyModule } = NativeModules;

/**
 * Generates a key pair for FIDO2 authentication
 * @param username The username to use as the key alias
 * @returns An object containing the public key and private key alias
 */
export async function generateKeyPair(email: string): Promise<{ publicKey: string, privateKeyAlias: string }> {
    try {
        // Create a unique key alias based on the username
        const keyAlias = `fido2_${email.replace(/[^a-zA-Z0-9]/g, '_')}`;

        // Call native module to generate the key pair
        const result = await SecureKeyModule.generateKeyPair(keyAlias);
        console.log("Key pair generated successfully:", result);

        // Convert standard base64 to base64url format for WebAuthn compatibility
        const publicKeyBase64Url = base64ToBase64Url(result.publicKey);

        return {
            publicKey: publicKeyBase64Url,
            privateKeyAlias: keyAlias
        };
    } catch (error: unknown) {
        console.error("Error generating key pair:", error);
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to generate key pair: ${errorMessage}`);
    }
}

/**
 * Signs data with the private key associated with the given alias
 * @param keyAlias The alias of the private key to use for signing
 * @param data The data to sign (already base64 encoded)
 * @returns Base64url-encoded signature
 */
export async function signWithPrivateKey(keyAlias: string, data: string): Promise<string> {
    try {
        // Verify input parameters
        if (!keyAlias) throw new Error("Key alias is required");
        if (!data) throw new Error("Data to sign is required");

        // Call native module to sign the data
        const signature = await SecureKeyModule.signData(keyAlias, data);
        console.log("Data signed successfully");

        // Convert standard base64 to base64url format for WebAuthn compatibility
        return base64ToBase64Url(signature);
    } catch (error: unknown) {
        console.error("Error signing data:", error);
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to sign data: ${errorMessage}`);
    }
}