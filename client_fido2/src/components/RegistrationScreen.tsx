// RegisterScreen.tsx
import React, { useState } from "react";
import { View, Text, TextInput, TouchableOpacity, Alert, Button } from "react-native";
import { register } from "../api/register";
import { theme } from "../theme";

export function RegisterScreen({ navigation }) {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");

    const handleRegister = async () => {
        if (!email || !password) {
            Alert.alert("Error", "Email and Password are required");
            return;
        }
        await register(email, password);
    };

    return (
        <View style={{ flex: 1, backgroundColor: theme.backgroundColor, padding: 20 }}>
            <Text style={{ color: theme.textColor, fontSize: 24, marginBottom: 20 }}>Register</Text>
            <TextInput
                style={{ backgroundColor: theme.inputBackground, color: theme.inputTextColor, padding: 10, marginBottom: 10 }}
                placeholder="Email"
                value={email}
                onChangeText={setEmail}
            />
            <TextInput
                style={{ backgroundColor: theme.inputBackground, color: theme.inputTextColor, padding: 10, marginBottom: 10 }}
                placeholder="Password"
                secureTextEntry
                value={password}
                onChangeText={setPassword}
            />
            <TouchableOpacity onPress={handleRegister} style={{ backgroundColor: theme.buttonColor, padding: 15, borderRadius: 5 }}>
                <Text style={{ color: "#000", textAlign: "center", fontWeight: "bold" }}>Register</Text>
            </TouchableOpacity>

            <Button
                title="Already have an account? Login"
                onPress={() => navigation.navigate('Login')}
            />
        </View>
    );
}