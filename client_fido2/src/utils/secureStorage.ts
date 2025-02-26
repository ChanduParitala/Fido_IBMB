import * as Keychain from "react-native-keychain";

export async function storeCredentials(email: string, privateKeyAlias: string) {
    await Keychain.setGenericPassword(email, privateKeyAlias, {
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });

    console.log("Stored credentials for", email, "inside secure storage");
}

export async function getStoredCredentials(email: string) {
    const credentials = await Keychain.getGenericPassword();
    console.log("Retrieved credentials from secure storage:", credentials);
    return credentials ? credentials.password : null;
}
