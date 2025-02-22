import axios from "axios";
import { LoginBody } from "../models/API";
import { LoginPath, LogoutPath, ManualLogin } from "../constants/API";
import { hasServiceError } from "./APIService";

export async function login(username: string, password: string, mac: string): Promise<void> {
    const response = await axios.post<any>(LoginPath, {
        username,
        password
    } as LoginBody);
    var error = hasServiceError(response);
    if (response.status !== 200 || error.errored) {
        throw new Error("Error while logging in: " + error.message);
    }
}

export async function logout(): Promise<boolean> {
    const response = await axios.get<any>(LogoutPath);

    return response.status === 200;
}

export async function radiusLogin(mac: string): Promise<void> {
    const response = await axios.post<any>(ManualLogin, {}, { params: { mac } });
    var error = hasServiceError(response);
    if (response.status !== 200 || error.errored) {
        throw new Error("Error while adding entry to RADIUS db: " + error.message);
    }
}