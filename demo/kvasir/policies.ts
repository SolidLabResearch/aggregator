import { randomUUID } from "crypto";
import { DataFactory, Store, Writer } from "n3";

const { namedNode, blankNode } = DataFactory;

interface PolicyOptions {
  name: string;
  assignee: string;
  assigner: string;
  target: string;
  scopes?: string[];
  container?: boolean;
  client?: string;
}

export async function createPolicies(policies: PolicyOptions[]): Promise<{ turtle: string; ids: string[] }> {
  const store = new Store();
  const policyIds: string[] = [];

  // Add all policies to store
  for (const p of policies) {
    const id = createPolicy(store, p);
    policyIds.push(id);
  }

  // Serialize store to Turtle
  const writer = new Writer({
    prefixes: {
      ex: `http://example.com/`,
      odrl: "http://www.w3.org/ns/odrl/2/",
      odrl_p: "https://w3id.org/force/odrl3proposal#",
      ldp: "http://www.w3.org/ns/ldp#",
      rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    },
  });

  writer.addQuads(store.getQuads(null, null, null, null));

  const turtle: string = await new Promise((resolve, reject) => {
    writer.end((err, result) => (err ? reject(err) : resolve(result)));
  });

  return { turtle, ids: policyIds };
}

export function createPolicy(store: Store, options: PolicyOptions): string {
  const { name, assignee, assigner, scopes = ["read"], target, container, client } = options;
  const uuid = randomUUID();
  const baseIRI = `http://example.com/${uuid}#`;

  const policyNode = namedNode(`${baseIRI}${name}Policy`);
  const permissionNode = namedNode(`${baseIRI}${name}Permission`);

  // Policy triples
  store.addQuad(policyNode, namedNode("rdf:type"), namedNode("odrl:Agreement"));
  store.addQuad(policyNode, namedNode("odrl:uid"), policyNode);
  store.addQuad(policyNode, namedNode("odrl:permission"), permissionNode);

  // Permission triples
  store.addQuad(permissionNode, namedNode("rdf:type"), namedNode("odrl:Permission"));
  scopes.forEach(scope => {
    store.addQuad(permissionNode, namedNode("odrl:action"), namedNode(`odrl:${scope}`));
  });
  store.addQuad(permissionNode, namedNode("odrl:assignee"), namedNode(assignee));
  store.addQuad(permissionNode, namedNode("odrl:assigner"), namedNode(assigner));

  // Target triples
  if (container) {
    const containerNode = namedNode(`collection:${target}:http://www.w3.org/ns/ldp#contains`);
    store.addQuad(permissionNode, namedNode("odrl:target"), containerNode);
  } else {
    store.addQuad(permissionNode, namedNode("odrl:target"), namedNode(target));
  }

  // Client triples
  if (client) {
    const constraintNode = namedNode(`${baseIRI}${name}ClientConstraint`);
    store.addQuad(permissionNode, namedNode("odrl:constraint"), constraintNode);
    store.addQuad(constraintNode, namedNode("odrl:leftOperand"), namedNode("odrl:purpose"));
    store.addQuad(constraintNode, namedNode("odrl:operator"), namedNode("odrl:eq"));
    store.addQuad(constraintNode, namedNode("odrl:rightOperand"), namedNode(`${client}`));
  }

  return policyNode.value;
}