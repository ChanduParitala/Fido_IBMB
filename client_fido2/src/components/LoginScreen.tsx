// LoginScreen.tsx
import React, { useState } from "react";
import { View, Text, TextInput, TouchableOpacity, Alert, Button } from "react-native";
import { login } from "../api/login";
import { theme } from "../theme";

export function LoginScreen({ navigation }) {
    const [email, setEmail] = useState("");

    const handleLogin = async () => {
        if (!email) {
            Alert.alert("Error", "Email is required");
            return;
        }
        await login(email);
    };

    return (
        <View style={{ flex: 1, backgroundColor: theme.backgroundColor, padding: 20 }}>
            <Text style={{ color: theme.textColor, fontSize: 24, marginBottom: 20 }}>Login</Text>
            <TextInput
                style={{ backgroundColor: theme.inputBackground, color: theme.inputTextColor, padding: 10, marginBottom: 10 }}
                placeholder="Email"
                value={email}
                onChangeText={setEmail}
            />
            <TouchableOpacity onPress={handleLogin} style={{ backgroundColor: theme.buttonColor, padding: 15, borderRadius: 5 }}>
                <Text style={{ color: "#000", textAlign: "center", fontWeight: "bold" }}>Login</Text>
            </TouchableOpacity>

            <Button
                title="Don't have an account? Sign Up"
                onPress={() => navigation.navigate('Register')}
            />
        </View>
    );
}