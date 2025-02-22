import React from "react";
import {
  performAttestationCeremony,
  performConditionalAssertionCeremony,
  performOptionalAssertionCeremony,
} from "../services/WebauthnService";
import {
  assertionMessage,
  attestationMessage,
} from "../services/MessagesService";

import { AssertionResult, AttestationResult } from "../models/Webauthn";
import { Button, Grid, Box } from "@mui/material";
import KeyIcon from "@mui/icons-material/Key";
import { getInfo } from "../services/APIService";
//import axios from "axios";
//import { hexMD5 } from "../utils/MD5.js";
import { radiusLogin } from "../services/ClientService";
interface Props {
  setDebugMessage: React.Dispatch<React.SetStateAction<string>>;
  setBothUsername(username: string): void;
  setFinalStage(state: boolean): void;
  loggedIn: boolean;
  mac: string;
}

const Webauthn = function (props: Props) {
  const { setBothUsername, setDebugMessage, setFinalStage, loggedIn, mac } =
    props;
  const [abortController, setAbortController] =
    React.useState<AbortController>();
  const [req, setReq] = React.useState<PublicKeyCredentialRequestOptions>();
  React.useEffect(() => {
    abortController?.abort();
    console.log("aborted");
    if (!loggedIn) {
      startConitionalAssertion();
    }
    // eslint-disable-next-line
  }, [loggedIn]);

  const handleDiscoverableLoginSuccess = React.useCallback(async () => {
    const info = await getInfo();
    if (info != null) {
      setBothUsername(info.username);
    }
  }, [setBothUsername]);

  const startConitionalAssertion = React.useCallback(() => {
    console.log("creating new abort controller");
    var abortControllerlocal = new AbortController();
    setAbortController(abortControllerlocal);
    console.log("created new abort controller", abortControllerlocal);
    console.log("running conditional assertion");
    performConditionalAssertionCeremony(mac, req, setReq, abortControllerlocal)
      .then(res => {
        if (res === AssertionResult.Success) {
          handleDiscoverableLoginSuccess();
        }
      })
      .catch(err => {
        console.log(err);
        setDebugMessage((err as Error).message);
      })
      .finally(() => {
        console.log("conditional assertion ended");
      });
  }, [handleDiscoverableLoginSuccess, setDebugMessage, mac, req]);

  const handleAttestationClick = async () => {
    setDebugMessage("Attempting Webauthn Attestation");
    abortController?.abort();
    await performAttestationCeremony(props.mac)
      .then(async result => {
        setDebugMessage(attestationMessage(result));
        if (result === AttestationResult.Success) {
          await handleDiscoverableLoginSuccess();
        }
      })
      .catch(err => {
        console.log(err);
        setDebugMessage((err as Error).message);
      });
  };

  const radiusAuth = async () => {
    await radiusLogin(mac);
    setFinalStage(true);
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
    setDebugMessage("Attempting Webauthn Assertion");
    //alert(searchParams.get('to'));
    console.log(abortController);
    abortController?.abort();
    console.log(abortController);
    console.log("old req", req);
    performOptionalAssertionCeremony(mac, req, setReq, new AbortController())
      .then(async result => {
        setDebugMessage(assertionMessage(result));
        if (result === AssertionResult.Success) {
          await handleDiscoverableLoginSuccess();
        }
        if (result === AssertionResult.FailureUserConsent) {
          startConitionalAssertion();
        }
      })
      .catch(err => {
        console.log(err);
        setDebugMessage((err as Error).message);
      });
  };

  return (
    <Grid container>
      <Grid item xs={12}>
        {loggedIn ? (
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
