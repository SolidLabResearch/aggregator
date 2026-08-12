import { randomUUID } from "node:crypto";
import { DataFactory } from "rdf-data-factory";
import { Parser, Store } from "n3";
import { serviceEndpointURL } from "./endpoints.js";
import { resolveService } from "./outputs.js";
import { authenticatedFetch, policiesEndpoint } from "./policies.js";

const df = new DataFactory();
const AGGR = "https://w3id.org/aggregator#";
const DCT = "http://purl.org/dc/terms/";
const ODRL_CONTEXT = "http://www.w3.org/ns/odrl.jsonld";

export interface AvailableRole { id: string; uri: string; title?: string; description?: string }
interface RoleGrant { permission?: unknown; [key: string]: unknown }

export async function listAvailableRoles(opts: { agg?: string; svc?: string } = {}) {
  const { service, roles } = await fetchAvailableRoles(opts);
  if (!roles.length) { console.log(`No access roles are available for service "${service.name}".`); return; }
  console.log(`Available roles for service "${service.name}":`);
  for (const role of roles) console.log(`${role.id}\t${role.uri}${role.title ? `\t${role.title}` : ""}${role.description ? `\t${role.description}` : ""}`);
}

export async function listActiveRoles(opts: { agg?: string; svc?: string } = {}) {
  const { aggregator, service } = resolveService(opts);
  const serviceURL = serviceEndpointURL(aggregator, service);
  const response = await (await authenticatedFetch())(`${policiesEndpoint(aggregator)}/grants`, { method: "GET", headers: { accept: "application/ld+json" } });
  const body = await response.text();
  if (!response.ok) throw new Error(`Failed to list active roles: HTTP ${response.status}${body ? `: ${body}` : ""}`);
  const active = ((body ? JSON.parse(body) : []) as RoleGrant[]).filter((grant) => jsonLDString(grant[`${AGGR}service`]) === serviceURL);
  if (!active.length) { console.log(`No active role grants exist for service "${service.name}".`); return; }
  console.log(`Active roles for service "${service.name}":`);
  for (const grant of active) {
    const uri = jsonLDString(grant[`${AGGR}role`]) ?? "(unknown role)";
    console.log(`${roleID(uri)}\t${agreementAssignees(grant).join(", ") || "(no assignee)"}\t${jsonLDString(grant[`${AGGR}grantId`]) ?? "(unknown grant)"}\t${uri}`);
  }
}

export async function assignRole(opts: { role: string; assignee: string; agg?: string; svc?: string }) {
  const { aggregator, service, roles } = await fetchAvailableRoles(opts);
  const selected = roles.find((role) => role.id === opts.role.trim() || role.uri === opts.role.trim());
  if (!selected) throw new Error(`Role "${opts.role}" is not available. Available roles: ${roles.map((role) => role.id).join(", ") || "none"}.`);
  const assignee = opts.assignee.trim(); if (!assignee) throw new Error("Assignee ID must not be empty.");
  const endpoint = new URL(`${policiesEndpoint(aggregator)}/grants`);
  endpoint.searchParams.set("service", serviceEndpointURL(aggregator, service)); endpoint.searchParams.set("role", selected.uri);
  const agreement = { "@context": ODRL_CONTEXT, "@type": "Agreement", uid: `urn:uuid:${randomUUID()}`, permission: [{ "@type": "Permission", assignee }] };
  const response = await (await authenticatedFetch())(endpoint, { method: "POST", headers: { accept: "application/ld+json", "content-type": "application/ld+json" }, body: JSON.stringify(agreement) });
  const body = await response.text(); if (!response.ok) throw new Error(`Failed to assign role: HTTP ${response.status}${body ? `: ${body}` : ""}`);
  console.log(`✅ Assigned role "${selected.id}" on service "${service.name}" to ${assignee}.`);
  const location = response.headers.get("location"); if (location) console.log(`Grant: ${location}`);
}

export async function fetchAvailableRoles(opts: { agg?: string; svc?: string } = {}) {
  const { aggregator, service } = resolveService(opts); const serviceURL = serviceEndpointURL(aggregator, service); const fetch = await authenticatedFetch();
  const response = await fetch(serviceURL, { method: "GET", headers: { accept: "text/turtle" } }); const body = await response.text();
  if (!response.ok) throw new Error(`Failed to fetch service description: HTTP ${response.status}${body ? `: ${body}` : ""}`);
  const store = new Store(new Parser({ format: "text/turtle", baseIRI: serviceURL }).parse(body));
  const uris = [...new Set(store.getObjects(df.namedNode(serviceURL), df.namedNode(`${AGGR}availableRoles`), null).filter((term) => term.termType === "NamedNode").map((term) => term.value))];
  const documents = new Map<string, Store>(); const roles: AvailableRole[] = [];
  for (const uri of uris) {
    const document = uri.split("#", 1)[0]; let profile = documents.get(document);
    if (!profile) { const res = await fetch(document, { method: "GET", headers: { accept: "text/turtle" } }); const text = await res.text(); if (!res.ok) throw new Error(`Failed to fetch role profile ${document}: HTTP ${res.status}${text ? `: ${text}` : ""}`); profile = new Store(new Parser({ format: "text/turtle", baseIRI: document }).parse(text)); documents.set(document, profile); }
    roles.push({ id: roleID(uri), uri, title: firstValue(profile, uri, `${DCT}title`), description: firstValue(profile, uri, `${DCT}description`) });
  }
  roles.sort((a, b) => a.id.localeCompare(b.id)); return { aggregator, service, roles };
}

function firstValue(store: Store, subject: string, predicate: string) { return store.getObjects(df.namedNode(subject), df.namedNode(predicate), null)[0]?.value; }
function roleID(uri: string) { const value = uri.includes("#") ? uri.slice(uri.lastIndexOf("#") + 1) : uri; return value.startsWith("role-") ? value.slice(5) : value; }
function agreementAssignees(grant: RoleGrant): string[] { const permissions = Array.isArray(grant.permission) ? grant.permission : grant.permission ? [grant.permission] : []; return [...new Set(permissions.flatMap((permission) => { if (!permission || typeof permission !== "object") return []; const value = Object.entries(permission as Record<string, unknown>).find(([key]) => key === "assignee" || key.endsWith("/assignee") || key.endsWith("#assignee"))?.[1]; return (Array.isArray(value) ? value : value === undefined ? [] : [value]).map(jsonLDString).filter((item): item is string => Boolean(item)); }))]; }
function jsonLDString(value: unknown): string | undefined { if (typeof value === "string") return value; if (value && typeof value === "object") { const object = value as Record<string, unknown>; if (typeof object["@id"] === "string") return object["@id"]; if (typeof object["@value"] === "string") return object["@value"]; } return undefined; }
