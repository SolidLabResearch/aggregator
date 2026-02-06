const express = require("express");
const cors = require("cors");
const { createHandler } = require("graphql-sse/lib/use/express");
const { schema, startMockStream } = require("./schema");

const app = express();
const PORT = process.env.PORT || 4001;

app.use(cors());
app.use(express.json());

// GraphQL over SSE endpoint
app.use(
  "/graphql",
  createHandler({
    schema,
  })
);

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Start generating mock subscription events
startMockStream();

app.listen(PORT, () => {
  console.log(`Mock GraphQL SSE server running on port ${PORT}`);
});
