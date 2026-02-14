const REGISTRATION = "https://aggregator.local/registration";
const AS_URL = "http://localhost:4000/uma";

function wait(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  // 1️⃣ Start device flow
  const startResp = await fetch(REGISTRATION, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      registration_type: "device_code"
    }),
  });

  if (startResp.status !== 202) {
    throw new Error(`Device flow start failed: ${startResp.statusText}`);
  }

  const startData = await startResp.json();

  const {
    state,
    interval = 5,
    verification_uri,
    verification_uri_complete,
    user_code,
  } = startData;

  console.log("====== DEVICE FLOW ======");
  if (user_code) console.log("User code:", user_code);

  if (verification_uri_complete) {
    console.log("Open this URL in your browser:");
    console.log(verification_uri_complete.replace("host.docker.internal", "localhost"));
  } else if (verification_uri) {
    console.log("Verification URI:", verification_uri.replace("host.docker.internal", "localhost"));
  }

  console.log("=========================");
  console.log("Polling for completion...");

  // 2️⃣ Poll using state
  while (true) {
    await wait(interval * 1000);

    const finishResp = await fetch(REGISTRATION, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        registration_type: "device_code",
        state: state,
      }),
    });

    if (finishResp.status === 202) {
      process.stdout.write(".");
      continue;
    }

    if (finishResp.status === 201) {
      const data = await finishResp.json();
      console.log("\n✅ Aggregator ready:");
      console.log(data);
      break;
    }

    if (finishResp.status === 400) {
      const errorText = await finishResp.text();
      throw new Error(`Device flow failed: ${errorText}`);
    }

    throw new Error(`Unexpected response: ${finishResp.status}`);
  }
}

await main().catch(err => {
  console.error("\n❌ Error:", err.message);
});

export {};