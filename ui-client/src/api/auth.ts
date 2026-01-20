import { generateCodeVerifier, generateCodeChallenge } from "./pkce";
import { config } from "@/config";
import axios from "axios";

export const buildLoginUrl = async () => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = crypto.randomUUID();

  // Save codeVerifier + state in localStorage
  localStorage.removeItem("pkce_code_verifier");
  localStorage.removeItem("pkce_state");
  localStorage.setItem("pkce_code_verifier", codeVerifier);
  localStorage.setItem("pkce_state", state);

  const authUrl = new URL(`${config.keycloak.url}/protocol/openid-connect/auth`);
  authUrl.searchParams.set("client_id", config.keycloak.clientId);
  authUrl.searchParams.set("redirect_uri", config.redirectUriBase + "/login/callback");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", config.keycloak.scope || "openid");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return authUrl.toString();
};

export const exchangeCodeForToken = async () => {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const returnedState = params.get("state");

  const storedState = localStorage.getItem("pkce_state");
  const codeVerifier = localStorage.getItem("pkce_code_verifier");

  if (!code || !returnedState || !storedState || !codeVerifier)
    throw new Error("PKCE code verifier or state missing");

  if (returnedState !== storedState)
    throw new Error("State mismatch - possible CSRF attack");

  console.log("Saved verifier:", localStorage.getItem("pkce_code_verifier"));
  console.log("Returned code:", code);

  const tokenUrl = `${config.keycloak.url}/protocol/openid-connect/token`;
  const body = new URLSearchParams();
  body.append("grant_type", "authorization_code");
  body.append("client_id", config.keycloak.clientId);
  body.append("redirect_uri", config.redirectUriBase + "/login/callback");
  body.append("code", code);
  body.append("code_verifier", codeVerifier);

  const res = await axios.post(tokenUrl, body, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });

  // cleanup
  localStorage.removeItem("pkce_code_verifier");
  localStorage.removeItem("pkce_state");

  return res.data.id_token;
};


