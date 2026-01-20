import axios from "axios";
import { config } from "@/config";

export interface RegistrationResponse {
  state: string;
  client_id: string;
  code_challenge_method: string;
  code_challenge: string;
}

export interface OIDCConfigResponse {
  authorization_endpoint: string;
}

export interface CallbackRequest {
  code: string;
  state: string;
  redirect_uri: string;
}

export interface RegistrationEndpoints {
  [key: string]: string;
}

export const startRegistration = async (asUrl: string) => {
  const idToken = localStorage.getItem("id_token");

  if (!idToken) throw new Error("Not logged in");

  const res = await axios.post(
    `${config.aggregatorBaseUrl}/registration`,
    {
      registration_type: "authorization_code",
      authorization_server: asUrl,
    },
    {
      headers: {
        Authorization: `Bearer ${idToken}`,
      },
    }
  );

  return res.data;
};


export const fetchAuthUrl = async (idpProvider: string): Promise<string> => {
  try {
    const base = idpProvider.replace(/\/$/, '');
    const res = await axios.get<OIDCConfigResponse>(`${base}/.well-known/openid-configuration`);
    return res.data.authorization_endpoint;
  } catch (err) {
    console.error("Failed to fetch OIDC config", err);
    throw new Error("Could not fetch authorization endpoint");
  }
};

export const buildRedirectUri = (authUrl: string, res: RegistrationResponse) => {
  const uri = new URL(authUrl);
  uri.searchParams.append("redirect_uri", `${config.redirectUriBase}/registration/callback`)
  uri.searchParams.append("state", res.state);
  uri.searchParams.append("scope", "openid offline_access");
  uri.searchParams.append("response_type", "code");
  uri.searchParams.append("client_id", res.client_id);
  uri.searchParams.append("code_challenge_method", res.code_challenge_method),
  uri.searchParams.append("code_challenge", res.code_challenge)
  return uri
}

export const completeRegistration = async (payload: CallbackRequest): Promise<RegistrationEndpoints> => {
  payload.redirect_uri = `${config.redirectUriBase}/callback`
  const res = await axios.post<RegistrationEndpoints>(`${config.aggregatorBaseUrl}/registration/callback`, payload);
  return res.data;
};
