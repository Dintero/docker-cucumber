import * as http from "node:http";

const port = parseInt(process.env.PORT ?? "8080", 10);

const server = http.createServer((req, res) => {
    const url = new URL(req.url || "", `http://${req.headers.host}`);
    const path = url.pathname;
    const statusCode = parseInt(path.slice(1), 10);
    res.writeHead(statusCode, { "Content-Type": "text/plain" });
    res.end(`HTTP Status Code: ${statusCode}\n`);
});

server.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});

const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 2000).unref();
};

process.on("SIGINT", () => shutdown());
process.on("SIGTERM", () => shutdown());
