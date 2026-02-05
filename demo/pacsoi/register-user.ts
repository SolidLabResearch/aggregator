import readline from "readline";

const REGISTRATION = "https://aggregator.local/registration";
const AS_URL = "http://wsl.local:4000/uma";

function waitForEnter() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise<void>((resolve) => {
    rl.question("Press Enter once you completed the login at the verification URL...", () => {
      rl.close();
      resolve();
    });
  });
}

async function main() {
  // 1️⃣ Start device code flow
  const startResp = await fetch(REGISTRATION, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      registration_type: "device_code",
      authorization_server: AS_URL,
    }),
  });

  if (!startResp.ok) {
    throw new Error(`Device code start failed: ${startResp.statusText}`);
  }

  const startData = await startResp.json();
  console.log("====== DEVICE CODE ======");
  console.log("User code:", startData.user_code);
  console.log("Verification URI:", startData.verification_uri);
  console.log("=========================");

  // 2️⃣ Wait for user input
  await waitForEnter();

  // 3️⃣ Finalize device code flow
  const finishResp = await fetch(REGISTRATION, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      registration_type: "device_code",
      device_code: startData.device_code
    }),
  });
  if (!finishResp.ok) {
    throw new Error(`Device code finalize failed: ${finishResp.statusText}`);
  }

  const finishData = await finishResp.json();
  console.log("=== DEVICE CODE FINALIZE ===");
  console.log(finishData);
}

await main().catch(console.error);

