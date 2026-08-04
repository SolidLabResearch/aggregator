export interface ServiceConfig {
  name: string;
  deploymentFunction: string;
  params: Record<string, string>;
  datasets: Record<string, Record<string, string>>;
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
    deploymentCatalog: string;
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
  server: { host: "", deploymentCatalog: "/deployments", svc: "/services", reg: "/registration" },
  auth: { username: "", password: "", clientId: "", clientSecret: "", idp: "", uma: "" },
  service: { name: "", deploymentFunction: "", params: {}, datasets: {} },
};
