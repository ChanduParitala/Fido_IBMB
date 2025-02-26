import { createClientData, getAppOrigin } from "../utils/fido2Utils";
import { getStoredCredentials } from "../utils/secureStorage";
import { signWithPrivateKey } from "../utils/cryptoUtils";
import { Alert } from "react-native";
import { Buffer } from "buffer";

export async function login(email: string) {
    try {
        console.log("Publishing call to server, LoginChallenge", email);
        // Request authentication challenge
        const response = await fetch("http://localhost:3000/api/login/challenge", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Failed to initiate login");
        }

        const loginData = await response.json();
        console.log("Received login data", loginData);
        const { challenge, allowCredentials } = loginData;
        console.log("Received challenge from fido2 server", challenge);

        if (!allowCredentials || allowCredentials.length === 0) {
            throw new Error("No credentials found for this user");
        }

        // Get the credential ID from the first credential
        const credentialId = allowCredentials[0].id;
        console.log("Using credential ID", credentialId);

        // Retrieve stored private key alias
        const privateKeyAlias = await getStoredCredentials(email);
        console.log("Retrieved private key alias", privateKeyAlias);

        if (!privateKeyAlias) {
            Alert.alert("No credentials found");
            return false;
        }

        // Sign challenge
        const signedChallenge = await signWithPrivateKey(privateKeyAlias, challenge);
        console.log("Signed challenge", signedChallenge);

        // Create client data for assertion
        const origin = await getAppOrigin();
        const clientData = createClientData('webauthn.get', challenge, origin);
        const clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString('base64');

        // Send signed challenge to server
        const result = await fetch("http://localhost:3000/api/login/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email,
                credentialId,
                clientDataJSON,
                signedChallenge
            }),
        });

        if (result.ok) {
            Alert.alert("Login Successful");
            return true;
        } else {
            const errorData = await result.json();
            Alert.alert("Login Failed", errorData.error || "Unknown error");
            return false;
        }
    } catch (error) {
        console.error("Login Error:", error);
        if (error instanceof Error) {
            Alert.alert("Login Error", error.message);
        } else {
            Alert.alert("Login Error");
        }
        return false;
    }
}