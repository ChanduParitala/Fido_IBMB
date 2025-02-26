import { NativeModules } from 'react-native';
import { Buffer } from 'buffer';

const { SecureKeyModule } = NativeModules;

interface ClientData {
    type: string;
    challenge: string;
    origin: string;
    crossOrigin: boolean;
}

// Convert string to Base64URL
export function stringToBase64Url(str: string): string {
    return Buffer.from(str)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Convert base64 to base64url
export function base64ToBase64Url(base64: string): string {
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

export async function getAppOrigin(): Promise<string> {
    try {
        const packageHash = await SecureKeyModule.getPackageHash();
        return `android:apk-key-hash:${packageHash}`;
    } catch (error) {
        console.error('Error getting package hash:', error);
        // Fallback to a default origin for development
        return 'android:apk-key-hash:+sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w=';
    }
}

// Create client data object for attestation or assertion
export function createClientData(
    type: 'webauthn.create' | 'webauthn.get',
    challenge: string,
    origin: string
): ClientData {
    return {
        type,
        challenge,
        origin,
        crossOrigin: false
    };
}

// Generate a random bytes buffer of specified length
export function generateRandomBuffer(length: number): Buffer {
    const arr = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        arr[i] = Math.floor(Math.random() * 256);
    }
    return Buffer.from(arr);
}

// Convert a JavaScript object to a base64 string
export function objectToBase64(obj: any): string {
    return Buffer.from(JSON.stringify(obj)).toString('base64');
}