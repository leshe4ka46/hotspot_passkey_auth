import axios from "axios";
import { LoginBody } from "../models/API";
import { LoginPath, LogoutPath, ManualLogin } from "../constants/API";

export async function login(username: string, password: string, mac: string): Promise<boolean> {
    const body: LoginBody = {
        username,
        password,
        mac
    };
    const response = await axios.post<any>(LoginPath, body).catch((err) => { });
    return response != null && response.status === 200;
}

export async function logout(): Promise<boolean> {
    const response = await axios.get<any>(LogoutPath);

    return response.status === 200;
}

export async function radiusLogin(mac: string): Promise<boolean> {
    const response = await axios.post<any>(ManualLogin, {}, { params: { mac } }).catch((err) => { });
    return response != null && response.status === 200;
}