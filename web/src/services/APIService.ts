import axios, { AxiosResponse } from "axios";
import { ErrorResponse, ServiceResponse } from "../models/API";
import { Info } from "../models/Info";
import { InfoPath } from "../constants/API";

function toErrorResponse<T>(resp: AxiosResponse<ServiceResponse<T>>): ErrorResponse | undefined {
    if (resp.data && "status" in resp.data && resp.data["status"] === "error") {
        return resp.data as ErrorResponse;
    }
    return undefined;
}

export function toData<T>(resp: void | AxiosResponse<ServiceResponse<T>>): T | undefined {
    if (resp?.data && "status" in resp.data && resp.data["status"] === "OK") {
        return resp.data.data as T;
    }
    return undefined;
}

export function hasServiceError<T>(resp: AxiosResponse<ServiceResponse<T>>) {
    const errResp = toErrorResponse(resp);
    if (errResp && errResp.status === "error") {
        return { errored: true, message: errResp.error };
    }
    return { errored: false, message: null };
}

export async function getInfo(): Promise<Info | undefined> {
    var response = await axios.get<ServiceResponse<Info>>(InfoPath);
    var error = hasServiceError(response);
    if (response.status !== 200 || error.errored) {
        throw new Error("Error getting info: " + error.message);
    }
    return toData<Info>(response);
}
