import axios from "axios";
import { config } from "@/config";

export interface RegistrationResponse {
  callback_uri: string;
  state: string;
  scope: string;
  response_type: string;
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

export const startRegistration = async (idpProvider: string, asUrl: string): Promise<RegistrationResponse> => {
  const res = await axios.post<RegistrationResponse>(`${config.aggregatorBaseUrl}/registration`, {
    openid_provider: idpProvider,
    as_url: asUrl,
  });
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
  uri.searchParams.append("redirect_uri", `${config.redirectUriBase}/callback`)
  uri.searchParams.append("state", res.state);
  uri.searchParams.append("scope", res.scope);
  uri.searchParams.append("response_type", res.response_type);
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
