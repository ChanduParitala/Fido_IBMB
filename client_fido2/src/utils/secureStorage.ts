import * as Keychain from "react-native-keychain";

export async function storeCredentials(email: string, privateKeyAlias: string) {
    await Keychain.setGenericPassword(email, privateKeyAlias, {
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
}

export async function getStoredCredentials(email: string) {
    const credentials = await Keychain.getGenericPassword();
    return credentials ? credentials.password : null;
}
