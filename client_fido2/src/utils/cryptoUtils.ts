import { NativeModules } from "react-native";
import * as SecureRandom from "react-native-securerandom";

const { SecureKeyModule } = NativeModules;

console.log("NativeModules from react-native: ", NativeModules);

// Generate Secure Random Bytes
export async function getRandomBytes(size: number): Promise<string> {
    const randomBytes = await SecureRandom.generateSecureRandom(size);
    return Array.from(randomBytes).map(byte => byte.toString(16).padStart(2, "0")).join("");
}


// Generate Key Pair
export async function generateKeyPair(email: string) {
    if (!SecureKeyModule) {
        throw new Error("SecureKeyModule is not available. Make sure it's correctly linked.");
    }

    const randomHex = await getRandomBytes(4); // Generate 4 bytes of random data
    const privateKeyAlias = `webauthn-${email}-${randomHex}`;
    const publicKey = await SecureKeyModule.generateKeyPair(privateKeyAlias);
    console.log("Generated key pair:", { publicKey, privateKeyAlias });

    return { publicKey, privateKeyAlias };
}

// Sign Data with Private Key
export async function signWithPrivateKey(privateKeyAlias: string, data: string) {
    if (!SecureKeyModule) {
        throw new Error("SecureKeyModule is not available. Make sure it's correctly linked.");
    }

    return await SecureKeyModule.signData(privateKeyAlias, data);
}
