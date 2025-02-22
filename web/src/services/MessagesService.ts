import {
    AssertionResult,
    AttestationResult
}
    from "../models/Webauthn";

export const attestationMessage = (result: AttestationResult) => {
    switch (result) {
        case AttestationResult.Success:
            return "Successful attestation.";
        case AttestationResult.FailureSupport:
            return "Your browser does not appear to support the configuration.";
        case AttestationResult.FailureSyntax:
            return "The attestation challenge was rejected as malformed or incompatible by your browser.";
        case AttestationResult.FailureWebauthnNotSupported:
            return "Your browser does not support the WebAuthN protocol.";
        case AttestationResult.FailureUserConsent:
            return "You cancelled the attestation request.";
        case AttestationResult.FailureUserVerificationOrResidentKey:
            return "Your device does not support user verification or resident keys but this was required.";
        case AttestationResult.FailureExcluded:
            return "You have registered this device already.";
        case AttestationResult.FailureUnknown:
            return "An unknown error occurred.";
    }
    return "An unexpected error occurred.";

}

export const assertionMessage = (result: AssertionResult) => {
    switch (result) {
        case AssertionResult.Success:
            return "Successful assertion.";
        case AssertionResult.FailureUserConsent:
            return "You cancelled the request.";
        case AssertionResult.FailureU2FFacetID:
            return "The server responded with an invalid Facet ID for the URL.";
        case AssertionResult.FailureSyntax:
            return "The assertion challenge was rejected as malformed or incompatible by your browser.";
        case AssertionResult.FailureWebauthnNotSupported:
            return "Your browser does not support the WebAuthN protocol.";
        case AssertionResult.FailureUnknownSecurity:
            return "An unknown security error occurred.";
        case AssertionResult.FailureUnknown:
            return "An unknown error occurred.";
    }
    return "An unexpected error occurred.";
}
