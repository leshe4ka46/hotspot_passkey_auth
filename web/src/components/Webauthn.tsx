import React from "react";
import {
  performAssertionCeremony,
  performAttestationCeremony,
} from "../services/WebauthnService";

import { AssertionResult, AttestationResult } from "../models/Webauthn";
import { Button, Grid, Box } from "@mui/material";
import KeyIcon from "@mui/icons-material/Key";
import { getInfo } from "../services/APIService";
//import axios from "axios";
//import { hexMD5 } from "../utils/MD5.js";
import { radiusLogin } from "../services/ClientService";
interface Props {
  setDebugMessage: React.Dispatch<React.SetStateAction<string>>;
  Discoverable: boolean;
  setBothUsername(username: string): void;
  setFinalStage(state: boolean): void;
  loggedIn: boolean;
  mac: string;
}

const Webauthn = function (props: Props) {
  const [abortController, setabortController] =
    React.useState<AbortController>();
  const [abortSignal, setabortSignal] = React.useState<AbortSignal>();
  const [req, setReq] = React.useState<PublicKeyCredentialRequestOptions>();
  React.useEffect(() => {
    abortController?.abort();
    if (!props.loggedIn) {
      var abortControllerlocal = new AbortController();
      setabortController(abortControllerlocal);
      setabortSignal(abortControllerlocal.signal);
      console.log(abortControllerlocal);
      console.log("got first time");
    }
    // eslint-disable-next-line
  }, [props.loggedIn]);
  React.useEffect(() => {
    if (!props.loggedIn && abortController) {
      console.log("running conditional attestation");
      performAssertionCeremony(
        true,
        props.mac,
        req,
        setReq,
        abortController
      ).then(res => {
        if (res === AssertionResult.Success) {
          handleDiscoverableLoginSuccess();
        }
      });
    }
    if (props.loggedIn) {
      abortController?.abort();
      console.log("aborted");
    }
    // eslint-disable-next-line
  }, [abortController, abortSignal, props.loggedIn, props.mac]);
  const handleDiscoverableLoginSuccess = async () => {
    const info = await getInfo();
    if (info != null) {
      props.setBothUsername(info.username);
    }
  };

  const handleAttestationClick = async () => {
    props.setDebugMessage("Attempting Webauthn Attestation");
    abortController?.abort();
    await performAttestationCeremony(props.mac)
      .then(result => {
        switch (result) {
          case AttestationResult.Success:
            props.setDebugMessage("Successful attestation.");
            handleDiscoverableLoginSuccess();
            break;
          case AttestationResult.FailureSupport:
            props.setDebugMessage(
              "Your browser does not appear to support the configuration."
            );
            break;
          case AttestationResult.FailureSyntax:
            props.setDebugMessage(
              "The attestation challenge was rejected as malformed or incompatible by your browser."
            );
            break;
          case AttestationResult.FailureWebauthnNotSupported:
            props.setDebugMessage(
              "Your browser does not support the WebAuthN protocol."
            );
            break;
          case AttestationResult.FailureUserConsent:
            props.setDebugMessage("You cancelled the attestation request.");
            break;
          case AttestationResult.FailureUserVerificationOrResidentKey:
            props.setDebugMessage(
              "Your device does not support user verification or resident keys but this was required."
            );
            break;
          case AttestationResult.FailureExcluded:
            props.setDebugMessage("You have registered this device already.");
            break;
          case AttestationResult.FailureUnknown:
            props.setDebugMessage("An unknown error occurred.");
            break;
        }
      })
      .catch(err => {
        console.log(err);
        props.setDebugMessage(err.response.data.error);
      });
  };

  const radiusAuth = () => {
    console.log("auth");
    radiusLogin(props.mac).then(ret => {
      if (ret) {
        props.setFinalStage(true);
      }
    });
    /*let url: string = searchParams.get('to')!;
    let mac: string = searchParams.get('mac')!;
    var bodyFormData = new FormData();
    bodyFormData.append("username", mac);
    bodyFormData.append(
      "password",
      hexMD5(
        (document.getElementById("chap-id") as HTMLInputElement)?.value +
          "8ud8HevunaNXmcTEcjkBWAzX0iuhc6JF" +
          (document.getElementById("chap-challenge") as HTMLInputElement)?.value
      )
    );

    axios({
      method: "post",
      url: url,
      data: bodyFormData,
      headers: { "Content-Type": "multipart/form-data" },
    })
      .then(function (response) {
        //handle success
        console.log(response);
      })
      .catch(function (response) {
        //handle error
        console.log(response);
      });*/
  };
  const handleAssertionClick = async () => {
    props.setDebugMessage("Attempting Webauthn Assertion");
    //alert(searchParams.get('to'));
    console.log(abortController);
    abortController?.abort();
    console.log(abortController);
    performAssertionCeremony(
      false,
      props.mac,
      req,
      setReq,
      new AbortController()
    )
      .then(async result => {
        switch (result) {
          case AssertionResult.Success:
            props.setDebugMessage("Successful assertion.");

            await handleDiscoverableLoginSuccess();
            break;
          case AssertionResult.FailureUserConsent:
            props.setDebugMessage("You cancelled the request.");
            break;
          case AssertionResult.FailureU2FFacetID:
            props.setDebugMessage(
              "The server responded with an invalid Facet ID for the URL."
            );
            break;
          case AssertionResult.FailureSyntax:
            props.setDebugMessage(
              "The assertion challenge was rejected as malformed or incompatible by your browser."
            );
            break;
          case AssertionResult.FailureWebauthnNotSupported:
            props.setDebugMessage(
              "Your browser does not support the WebAuthN protocol."
            );
            break;
          case AssertionResult.FailureUnknownSecurity:
            props.setDebugMessage("An unknown security error occurred.");
            break;
          case AssertionResult.FailureUnknown:
            props.setDebugMessage("An unknown error occurred.");
            break;
          default:
            props.setDebugMessage("An unexpected error occurred.");
            break;
        }
      })
      .catch(err => {
        console.log(err);
        props.setDebugMessage(err.response.data.error);
      });
  };

  return (
    <Grid container>
      <Grid item xs={12}>
        {props.loggedIn ? (
          <Box>
            <Button
              fullWidth
              variant="contained"
              onClick={async () => {
                await handleAttestationClick();
              }}>
              Создать ключ
            </Button>
            <Box sx={{ m: 0.5 }} />
            <Button fullWidth onClick={radiusAuth}>
              Продожить без создания ключа
            </Button>
          </Box>
        ) : (
          <Button
            fullWidth
            variant="contained"
            onClick={async () => {
              await handleAssertionClick();
            }}
            startIcon={<KeyIcon />}>
            Вход с ключом
          </Button>
        )}
      </Grid>
    </Grid>
  );
};

export default Webauthn;
