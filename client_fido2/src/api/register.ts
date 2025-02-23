import { generateKeyPair, signWithPrivateKey } from "../utils/cryptoUtils";
import { storeCredentials } from "../utils/secureStorage";
import { Alert } from "react-native";

export async function register(email: string, password: string) {
    try {
        console.log("Publishing call to server, RegisterInit", email)
        // Request registration challenge from server
        const response = await fetch("http://192.168.1.13:3000/api/register/init", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        });

        const { challenge } = await response.json();

        console.log("Received challenge from fido2 server", challenge)

        // Generate key pair stored in TPM
        const { publicKey, privateKeyAlias } = await generateKeyPair(email);

        // Sign challenge
        const signedChallenge = await signWithPrivateKey(privateKeyAlias, challenge);

        // Send signed challenge + public key to server
        const result = await fetch("http://192.168.1.13:3000/api/register/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, publicKey, signedChallenge }),
        });

        if (result.ok) {
            await storeCredentials(email, privateKeyAlias);
            Alert.alert("Registration Successful");
        } else {
            Alert.alert("Registration Failed");
        }
    } catch (error) {
        console.error("Registration Error:", error);
    }
}
