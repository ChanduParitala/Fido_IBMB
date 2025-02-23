import { getStoredCredentials } from "../utils/secureStorage";
import { signWithPrivateKey } from "../utils/cryptoUtils";
import { Alert } from "react-native";

export async function login(email: string) {
    try {
        // Request authentication challenge
        const response = await fetch("http://192.168.1.13:3000/api/login/init", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email }),
        });

        const { challenge } = await response.json();

        // Retrieve stored private key alias
        const privateKeyAlias = await getStoredCredentials(email);

        if (!privateKeyAlias) {
            Alert.alert("No credentials found");
            return;
        }

        // Sign challenge
        const signedChallenge = await signWithPrivateKey(privateKeyAlias, challenge);

        // Send signed challenge to server
        const result = await fetch("http://192.168.1.13:3000/api/login/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, signedChallenge }),
        });

        if (result.ok) {
            Alert.alert("Login Successful");
        } else {
            Alert.alert("Login Failed");
        }
    } catch (error) {
        console.error("Login Error:", error);
    }
}
