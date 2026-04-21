export interface ServiceConfig {
  name: string;
  tf: string;
  params: Record<string, string>;
  outputs: string[];
}

export interface AggregatorConfig {
  id: string;
  services: Record<string, ServiceConfig>;
}

export interface AuthConfig {
  username: string;
  password: string;
  clientId: string;
  clientSecret: string;
  idp: string;
  uma: string;
}

export interface TLSConfig {
  devMode?: boolean;
  caCert?: string;
}

export interface Config {
  activeAggregator: string | null;
  aggregators: Record<string, AggregatorConfig>;
  server: {
    host: string;
    tf: string;
    svc: string;
    reg: string;
  };
  auth: AuthConfig;
  service: ServiceConfig;
  tls?: TLSConfig;
}

export const defaults: Config = {
  activeAggregator: null,
  aggregators: {},
  server: { host: "", tf: "/transformations", svc: "/services", reg: "/register" },
  auth: { username: "", password: "", clientId: "", clientSecret: "", idp: "", uma: "" },
  service: { name: "", tf: "", params: {}, outputs: [] },
};