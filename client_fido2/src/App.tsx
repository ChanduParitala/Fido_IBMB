import React from "react";
import { NavigationContainer } from "@react-navigation/native";
import { createStackNavigator } from "@react-navigation/stack";
import { LoginScreen } from "./components/LoginScreen";
import { RegisterScreen } from "./components/RegistrationScreen";

const Stack = createStackNavigator();

const App = () => {
    return (
        <NavigationContainer>
            <Stack.Navigator initialRouteName="Login">
                <Stack.Screen name="Login" component={LoginScreen} />
                <Stack.Screen name="Register" component={RegisterScreen} />
            </Stack.Navigator>
        </NavigationContainer>
    );
};

export default App;
