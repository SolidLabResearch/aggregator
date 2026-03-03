import { createPolicies } from "./policies.js";
import { KvasirManagement } from "./management.js";

const POD_URL = "http://localhost:8080/alice";
const AS_SERVER = "http://localhost:4000/uma"
const IDP = "http://localhost:8280";
const REALM = "quarkus";
const CLIENT_ID = "demo-client";
const CLIENT_UMA_ID = `http://example.com/id/${CLIENT_ID}`;
const CLIENT_SECRET = "SsIyMNGjbKrbcJPHr8gWwc36DdqMGvvd";

const USER_ID = "3744e254-9865-4c42-a1f0-ee03f866c186";
const USER_UMA_ID = `http://example.com/id/${USER_ID}`;
const USERNAME = "alice@example.com";
const PASSWORD = "alice";
const DOCTOR_ID = "7cbe4aea-f394-4907-969a-0387a9774273";
const DOCTOR_UMA_ID = `http://example.com/id/${DOCTOR_ID}`

const kvasir = new KvasirManagement(POD_URL, AS_SERVER);
await kvasir.init(IDP, REALM);
await kvasir.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

async function test() {
  await kvasir.readPolicies(USER_UMA_ID);
}

test()