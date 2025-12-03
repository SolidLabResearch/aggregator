const http = require('http');

const server = http.createServer((req, res) => {
  let body = [];

  req.on('data', chunk => {
    body.push(chunk);
  });

  req.on('end', () => {
    body = Buffer.concat(body).toString();

    console.log("---- Incoming Request ----");
    console.log("Method:", req.method);
    console.log("URL:", req.url);
    console.log("Headers:", req.headers);
    console.log("Body:", body);
    console.log("--------------------------");

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('hey there!');
  });
});

const port = 6000;
server.listen(port, () => {
  console.log(`Dummy server running on port ${port}`);
});
