import { getBase64WebEncodingFromBytes, getBytesFromBase64 } from '../utils/Base64';
import {
    AssertionPublicKeyCredentialResult,
    AssertionResult,
    AttestationPublicKeyCredential,
    AttestationPublicKeyCredentialJSON,
    AttestationPublicKeyCredentialResult,
    AttestationResult,
    AuthenticatorAttestationResponseFuture, CredentialCreation, CredentialRequest,
    PublicKeyCredentialCreationOptionsJSON,
    PublicKeyCredentialCreationOptionsStatus,
    PublicKeyCredentialDescriptorJSON,
    PublicKeyCredentialJSON,
    PublicKeyCredentialRequestOptionsJSON,
    PublicKeyCredentialRequestOptionsStatus
} from '../models/Webauthn';
import axios from "axios";
import { OptionalDataServiceResponse, ServiceResponse, SignInResponse } from "../models/API";
import { AssertionPath, AttestationPath } from "../constants/API";

import { hasServiceError, toData } from './APIService';

export function isWebauthnSecure(): boolean {
    if (window.isSecureContext) {
        return true;
    }

    return (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1");
}

export function isWebauthnSupported(): boolean {
    return window?.PublicKeyCredential !== undefined && typeof window.PublicKeyCredential === "function";
}

export async function isWebauthnPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (!isWebauthnSupported()) {
        return false;
    }

    return window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}

function arrayBufferEncode(value: ArrayBuffer): string {
    return getBase64WebEncodingFromBytes(new Uint8Array(value));
}

function arrayBufferDecode(value: string): ArrayBuffer {
    return getBytesFromBase64(value).buffer;
}

function decodePublicKeyCredentialDescriptor(descriptor: PublicKeyCredentialDescriptorJSON): PublicKeyCredentialDescriptor {
    return {
        id: arrayBufferDecode(descriptor.id),
        type: descriptor.type,
        transports: descriptor.transports,
    }
}

function decodePublicKeyCredentialCreationOptions(options: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptions {
    return {
        attestation: options.attestation,
        authenticatorSelection: options.authenticatorSelection,
        challenge: arrayBufferDecode(options.challenge),
        excludeCredentials: options.excludeCredentials?.map(decodePublicKeyCredentialDescriptor),
        extensions: options.extensions,
        pubKeyCredParams: options.pubKeyCredParams,
        rp: options.rp,
        timeout: options.timeout,
        user: {
            displayName: options.user.displayName,
            id: arrayBufferDecode(options.user.id),
            name: options.user.name,
        },
    };
}

function decodePublicKeyCredentialRequestOptions(options: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions {
    let allowCredentials: PublicKeyCredentialDescriptor[] | undefined = undefined;

    if (options.allowCredentials?.length !== 0) {
        allowCredentials = options.allowCredentials?.map(decodePublicKeyCredentialDescriptor);
    }

    return {
        allowCredentials: allowCredentials,
        challenge: arrayBufferDecode(options.challenge),
        extensions: options.extensions,
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification,
    };
}

function encodeAttestationPublicKeyCredential(credential: AttestationPublicKeyCredential): AttestationPublicKeyCredentialJSON {
    const response = credential.response as AuthenticatorAttestationResponseFuture;

    let transports: AuthenticatorTransport[] | undefined;

    if (response?.getTransports !== undefined && typeof response.getTransports === 'function') {
        transports = response.getTransports();
    }
    return {
        id: credential.id,
        type: credential.type,
        rawId: arrayBufferEncode(credential.rawId),
        clientExtensionResults: credential.getClientExtensionResults(),
        response: {
            attestationObject: arrayBufferEncode(response.attestationObject),
            clientDataJSON: arrayBufferEncode(response.clientDataJSON),

        },
        transports: transports,
        authenticatorAttachment: credential.authenticatorAttachment
    };
}

function encodeAssertionPublicKeyCredential(credential: PublicKeyCredential): PublicKeyCredentialJSON {
    const response = credential.response as AuthenticatorAssertionResponse;

    let userHandle: string;

    if (response.userHandle == null) {
        userHandle = "";
    } else {
        userHandle = arrayBufferEncode(response.userHandle)
    }
    return {
        id: credential.id,
        type: credential.type,
        rawId: arrayBufferEncode(credential.rawId),
        clientExtensionResults: credential.getClientExtensionResults(),
        response: {
            authenticatorData: arrayBufferEncode(response.authenticatorData),
            clientDataJSON: arrayBufferEncode(response.clientDataJSON),
            signature: arrayBufferEncode(response.signature),
            userHandle: userHandle,
        },
        authenticatorAttachment: null
    };

}

function getAttestationResultFromDOMException(exception: DOMException): AttestationResult {
    // Docs for this section:
    // https://w3c.github.io/webauthn/#sctn-op-make-cred
    switch (exception.name) {
        case 'UnknownError':
            // § 6.3.2 Step 1 and Step 8.
            return AttestationResult.FailureSyntax;
        case 'NotSupportedError':
            // § 6.3.2 Step 2.
            return AttestationResult.FailureSupport;
        case 'InvalidStateError':
            // § 6.3.2 Step 3.
            return AttestationResult.FailureExcluded;
        case 'NotAllowedError':
            // § 6.3.2 Step 3 and Step 6.
            return AttestationResult.FailureUserConsent;
        // § 6.3.2 Step 4.
        case 'ConstraintError':
            return AttestationResult.FailureUserVerificationOrResidentKey;
        default:
            console.log(`Unhandled DOMException occurred during WebAuthN attestation: ${exception}`);
            return AttestationResult.FailureUnknown;
    }
}

function getAssertionResultFromDOMException(exception: DOMException, requestOptions: PublicKeyCredentialRequestOptions): AssertionResult {
    // Docs for this section:
    // https://w3c.github.io/webauthn/#sctn-op-get-assertion
    switch (exception.name) {
        case 'UnknownError':
            // § 6.3.3 Step 1 and Step 12.
            return AssertionResult.FailureSyntax;
        case 'NotAllowedError':
            // § 6.3.3 Step 6 and Step 7.
            return AssertionResult.FailureUserConsent;
        case 'SecurityError':
            // § 10.1 and 10.2 Step 3.
            if (requestOptions.extensions?.appid !== undefined) {
                return AssertionResult.FailureU2FFacetID;
            } else {
                return AssertionResult.FailureUnknownSecurity;
            }
        default:
            console.log(`Unhandled DOMException occurred during WebAuthN assertion: ${exception}`);
            return AssertionResult.FailureUnknown;
    }
}

async function getAttestationCreationOptions(): Promise<PublicKeyCredentialCreationOptionsStatus> {

    var response = await axios.get<ServiceResponse<CredentialCreation>>(AttestationPath);
    var error = hasServiceError(response);
    if (response.status !== 200 || error.errored) {
        throw new Error("Error: " + error.message);
    }

    const data = toData<CredentialCreation>(response);
    return {
        options: decodePublicKeyCredentialCreationOptions(data?.publicKey!),
        status: response.status,
    };
}

async function getAssertionRequestOptions(): Promise<PublicKeyCredentialRequestOptionsStatus> {
    var response = await axios.get<ServiceResponse<CredentialRequest>>(AssertionPath);
    var error = hasServiceError(response);
    if (response.status !== 200 || error.errored) {
        throw new Error("Error: " + error.message);
    }

    const data = toData<CredentialRequest>(response);
    return {
        options: decodePublicKeyCredentialRequestOptions(data?.publicKey!),
        status: response.status,
    };
}

async function getAttestationPublicKeyCredentialResult(creationOptions: PublicKeyCredentialCreationOptions): Promise<AttestationPublicKeyCredentialResult> {
    const result: AttestationPublicKeyCredentialResult = {
        result: AttestationResult.Success,
    };

    try {
        result.credential = (await navigator.credentials.create({ publicKey: creationOptions })) as AttestationPublicKeyCredential;
    } catch (e) {
        result.result = AttestationResult.Failure;

        const exception = e as DOMException;
        if (exception !== undefined) {
            result.result = getAttestationResultFromDOMException(exception);

            return result;
        } else {
            console.error(`Unhandled exception occurred during WebAuthN attestation: ${e}`);
        }
    }

    if (result.credential == null) {
        result.result = AttestationResult.Failure;
    } else {
        result.result = AttestationResult.Success;
    }

    return result;
}

async function getAssertionPublicKeyCredentialResult(conditional: boolean, requestOptions: PublicKeyCredentialRequestOptions, abortController: AbortController): Promise<AssertionPublicKeyCredentialResult> {
    const result: AssertionPublicKeyCredentialResult = {
        result: AssertionResult.Success,
    };
    try {
        result.credential = (await navigator.credentials.get({
            ...(conditional ? { signal: abortController.signal } : {}),
            mediation: (conditional ? "conditional" : "optional") as CredentialMediationRequirement,
            publicKey: requestOptions
        })) as PublicKeyCredential;
    } catch (e) {
        result.result = AssertionResult.Failure;

        const exception = e as DOMException;
        if (exception !== undefined) {
            result.result = getAssertionResultFromDOMException(exception, requestOptions);

            return result;
        } else {
            console.error(`Unhandled exception occurred during WebAuthN assertion: ${e}`);
        }
    }

    if (result.credential == null) {
        result.result = AssertionResult.Failure;
    } else {
        result.result = AssertionResult.Success;
    }

    return result;
}

async function postAttestationPublicKeyCredentialResult(credential: AttestationPublicKeyCredential, mac: string) {
    const credentialJSON = encodeAttestationPublicKeyCredential(credential);

    var response = await axios.post<ServiceResponse<OptionalDataServiceResponse<any>>>(AttestationPath, credentialJSON, { params: { mac } });
    var error = hasServiceError(response);
    if (response.status !== 200 || error.errored) {
        throw new Error("Error: " + error.message);
    }
    return toData<OptionalDataServiceResponse<any>>(response);
}

async function postAssertionPublicKeyCredentialResult(credential: PublicKeyCredential, mac: string) {
    const credentialJSON = encodeAssertionPublicKeyCredential(credential);

    var response = await axios.post<ServiceResponse<SignInResponse>>(AssertionPath, credentialJSON, { params: { mac } })
    var error = hasServiceError(response);
    if (response.status !== 200 || error.errored) {
        throw new Error("Error: " + error.message);
    }
    return toData<SignInResponse>(response);
}

export async function performAttestationCeremony(mac: string): Promise<AttestationResult> {
    const attestationCreationOpts = await getAttestationCreationOptions();

    if (attestationCreationOpts.status !== 200 || attestationCreationOpts.options == null) {
        return AttestationResult.Failure;
    }

    const attestationResult = await getAttestationPublicKeyCredentialResult(attestationCreationOpts.options);

    if (attestationResult.result !== AttestationResult.Success) {
        return attestationResult.result;
    } else if (attestationResult.credential == null) {
        return AttestationResult.Failure;
    }

    await postAttestationPublicKeyCredentialResult(attestationResult.credential, mac);
    return AttestationResult.Success;
}

export async function performAssertionCeremony(conditional: boolean, mac: string, req: PublicKeyCredentialRequestOptions | undefined, setReq: React.Dispatch<React.SetStateAction<PublicKeyCredentialRequestOptions | undefined>>, abortController: AbortController): Promise<AssertionResult> {

    const assertionRequestOpts = (req === undefined) ? await getAssertionRequestOptions() : { options: req, status: 200 };
    if (assertionRequestOpts.status !== 200 || assertionRequestOpts.options == null) {
        return AssertionResult.Failure;
    }

    setReq(assertionRequestOpts.options);
    console.log("setreq", assertionRequestOpts.options);
    const assertionResult = await getAssertionPublicKeyCredentialResult(conditional, assertionRequestOpts.options, abortController);
    if (assertionResult.result !== AssertionResult.Success) {
        return assertionResult.result;
    } else if (assertionResult.credential == null) {
        return AssertionResult.Failure;
    }
    setReq(undefined);
    await postAssertionPublicKeyCredentialResult(assertionResult.credential, mac);
    return AssertionResult.Success;
}

export async function performConditionalAssertionCeremony(mac: string, req: PublicKeyCredentialRequestOptions | undefined, setReq: React.Dispatch<React.SetStateAction<PublicKeyCredentialRequestOptions | undefined>>, abortController: AbortController): Promise<AssertionResult> {
    return performAssertionCeremony(true, mac, req, setReq, abortController);
}

export async function performOptionalAssertionCeremony(mac: string, req: PublicKeyCredentialRequestOptions | undefined, setReq: React.Dispatch<React.SetStateAction<PublicKeyCredentialRequestOptions | undefined>>, abortController: AbortController): Promise<AssertionResult> {
    return performAssertionCeremony(false, mac, req, setReq, abortController);
}