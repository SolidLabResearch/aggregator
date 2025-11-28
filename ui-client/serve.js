import http from "http";
import fs from "fs";
import path from "path";
import url from "url";

const PORT = 3000;
const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, "public");

const mime = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg"
};

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url);
  let pathname = parsed.pathname;

  if (pathname === "/") pathname = "/index.html";

  const filePath = path.join(PUBLIC, pathname);
  const ext = path.extname(filePath);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }

    res.writeHead(200, { "Content-Type": mime[ext] || "text/plain" });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log("UI available at http://localhost:" + PORT);
});
