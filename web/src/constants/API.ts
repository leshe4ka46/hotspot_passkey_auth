import { getEmbeddedVariable } from "../utils/Configuration";

const ExternalURL = getEmbeddedVariable("externalurl")

export const AttestationPath = ExternalURL + "/api/webauthn/attestation";
export const AssertionPath = ExternalURL + "/api/webauthn/assertion";
export const LoginPath = ExternalURL + "/api/login";
export const LogoutPath = ExternalURL + "/api/logout";
export const InfoPath = ExternalURL + "/api/info";
export const ManualLogin = ExternalURL + "/api/radius/login";