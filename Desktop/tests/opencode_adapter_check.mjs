import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const [pluginFile, directory, secret] = process.argv.slice(2);
const plugin = (await import(pathToFileURL(pluginFile).href)).default;
const legacy = await plugin.server({ directory });
const configuration = {};
await legacy.config(configuration);
assert.equal(configuration.mcp.adr_context.type, "local");
assert.equal(configuration.mcp.adr_context.enabled, true);
const preserved = { mcp: { adr_context: { type: "local", command: ["/other/server"] } } };
await legacy.config(preserved);
assert.deepEqual(preserved.mcp.adr_context.command, ["/other/server"]);
await assert.rejects(
  legacy["tool.execute.before"]({ tool: "read", sessionID: "synthetic" }, { args: { filePath: "secret.txt" } }),
  error => /vault/i.test(error.message) && !error.message.includes(secret),
);
const safe = { title: "Normal", output: "ordinary result", metadata: {} };
await legacy["tool.execute.after"]({ tool: "read", args: {}, sessionID: "synthetic" }, safe);
assert.equal(safe.output, "ordinary result");
const sensitive = { title: "Result", output: secret, metadata: { copy: secret }, attachments: [secret] };
await legacy["tool.execute.after"]({ tool: "read", args: {}, sessionID: "synthetic" }, sensitive);
assert.match(sensitive.output, /vault/i);
assert.equal(JSON.stringify(sensitive).includes(secret), false);
assert.equal("attachments" in sensitive, false);

const callbacks = new Map();
const servers = new Map();
await plugin.setup({
  location: { directory: "/must-not-use-plugin-location" },
  session: { get: async () => ({ location: { directory } }) },
  tool: { hook: async (name, callback) => callbacks.set(name, callback) },
  mcp: { transform: async callback => callback({
    get: name => servers.get(name),
    set: (name, value) => servers.set(name, value),
  }) },
});
assert.equal(servers.get("adr_context").type, "local");
assert.equal(servers.get("adr_context").disabled, false);
await assert.rejects(
  callbacks.get("execute.before")({ tool: "read", input: { filePath: "secret.txt" }, sessionID: "synthetic" }),
  error => /vault/i.test(error.message) && !error.message.includes(secret),
);
const completed = {
  tool: "read", input: {}, sessionID: "synthetic", status: "success",
  result: { content: "text", metadata: { credential: secret } },
};
await callbacks.get("execute.after")(completed);
assert.equal(JSON.stringify(completed.result).includes(secret), false);
assert.match(completed.result.content, /vault/i);
const failed = {
  tool: "read", input: {}, sessionID: "synthetic", status: "error",
  error: { message: "Failure", details: secret },
};
await callbacks.get("execute.after")(failed);
assert.match(failed.error.message, /vault/i);
assert.equal(JSON.stringify(failed.error).includes(secret), false);
console.log("opencode V1/V2 hook and Context registration contracts passed");
