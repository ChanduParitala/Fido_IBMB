import { generateKeyPair, signWithPrivateKey } from "../utils/cryptoUtils";
import { storeCredentials, getStoredCredentials } from "../utils/secureStorage";
import { createClientData, getAppOrigin } from "../utils/fido2Utils";
import { Alert } from "react-native";
import { Buffer } from "buffer";

export async function register(email: string, password: string) {
    try {
        console.log("Publishing call to server, RegisterInit", email);
        // Request registration challenge from server
        const response = await fetch("http://localhost:3000/api/register/init", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Failed to initiate registration");
        }

        const registrationData = await response.json();
        console.log("Received registration data", registrationData);
        const { challenge } = registrationData;
        console.log("Received challenge from fido2 server", challenge);

        // Generate key pair stored in TPM
        const { publicKey, privateKeyAlias } = await generateKeyPair(email);
        console.log("Key pair generated", { publicKey, privateKeyAlias });

        // Sign challenge
        if (!privateKeyAlias) {
            throw new Error("Private key alias not found");
        }
        const signedChallenge = await signWithPrivateKey(privateKeyAlias, challenge);
        console.log("Signed challenge", signedChallenge);

        // Create client data for attestation
        const origin = await getAppOrigin();
        const clientData = createClientData('webauthn.create', challenge, origin);
        const clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString('base64');

        // Prepare data to send to server
        const registrationPayload = {
            email,
            publicKey,
            clientDataJSON,
            signedChallenge
        };

        // Send data to server for CBOR encoding and verification
        const result = await fetch("http://localhost:3000/api/register/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(registrationPayload),
        });
        console.log("Received response from server", result);

        if (result.ok) {
            await storeCredentials(email, privateKeyAlias);
            Alert.alert("Registration Successful");
            return true;
        } else {
            const errorData = await result.json();
            Alert.alert("Registration Failed", errorData.error || "Unknown error");
            return false;
        }
    } catch (error) {
        console.error("Registration Error:", error);
        if (error instanceof Error) {
            Alert.alert("Registration Error", error.message);
        } else {
            Alert.alert("Registration Error");
        }
        return false;
    }
}

export async function login(email: string) {
    try {
        // Request login challenge
        const response = await fetch("http://localhost:3000/api/login/challenge", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Failed to initiate login");
        }

        const { challenge, allowCredentials } = await response.json();
        console.log("Received login challenge", challenge);

        if (!allowCredentials || allowCredentials.length === 0) {
            throw new Error("No credentials found for this user");
        }

        // Get the credential ID from the first credential
        const credentialId = allowCredentials[0].id;

        // Retrieve private key alias from secure storage
        const privateKeyAlias = await getStoredCredentials(email);

        if (!privateKeyAlias) {
            throw new Error("Private key alias not found");
        }

        // Sign the challenge with the private key
        const signedChallenge = await signWithPrivateKey(privateKeyAlias, challenge);

        // Create client data for assertion
        const origin = await getAppOrigin();
        const clientData = createClientData('webauthn.get', challenge, origin);
        const clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString('base64');

        // Send data to server
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