// ADR managed plugin: adr-desktop-file-guard
// Local only. Supports the documented OpenCode 1.18.29+ server and V2 setup interfaces.
import { spawn } from "node:child_process";
import { isAbsolute } from "node:path";

const bridge = __ADR_BRIDGE_ARGUMENTS__;
const contextServer = __ADR_CONTEXT_SERVER__;
const contextRoot = __ADR_CONTEXT_ROOT__;
const serverName = __ADR_SERVER_NAME__;
const unavailable = "ADR could not check this operation. Open ADR to review the protection connection.";
const blocked = { blocked: true, permissionDecision: "deny", message: unavailable, permissionDecisionReason: unavailable };

function check(event, phase) {
  return new Promise(resolve => {
    let raw;
    try { raw = JSON.stringify(event); } catch { resolve(blocked); return; }
    if (Buffer.byteLength(raw) > 8 * 1024 * 1024) { resolve(blocked); return; }
    const child = spawn(bridge[0], [...bridge.slice(1), ...(phase === "post" ? ["post"] : [])], {
      shell: false, stdio: ["pipe", "pipe", "ignore"],
      ...(contextRoot ? { env: { ...process.env, ADR_PLUGIN_ROOT: contextRoot } } : {}),
    });
    let text = "", completed = false;
    const finish = value => {
      if (completed) return;
      completed = true; clearTimeout(timer); resolve(value);
    };
    const timer = setTimeout(() => { child.kill("SIGKILL"); finish(blocked); }, phase === "post" ? 5000 : 125000);
    child.on("error", () => finish(blocked));
    child.stdin.on("error", () => { child.kill("SIGKILL"); finish(blocked); });
    child.stdout.on("data", data => {
      text += data.toString("utf8");
      if (text.length > 4096) { child.kill("SIGKILL"); finish(blocked); }
    });
    child.on("close", code => {
      if (code !== 0) { finish(blocked); return; }
      try {
        const result = JSON.parse(text);
        if (!result || Array.isArray(result) || typeof result !== "object") { finish(blocked); return; }
        if (Object.keys(result).length === 0) { finish(result); return; }
        if (phase === "post" && result.blocked === true && typeof result.message === "string") {
          finish(result); return;
        }
        if (phase === "pre" && result.permissionDecision === "deny") { finish(result); return; }
      } catch {}
      finish(blocked);
    });
    child.stdin.end(raw);
  });
}

function event(tool, args, session, cwd, result) {
  if (typeof cwd !== "string" || !isAbsolute(cwd)) throw new Error(unavailable);
  return {
    tool_name: tool, tool_input: args || {}, session_id: session || "", cwd,
    ...(result === undefined ? {} : { tool_response: result }),
  };
}

export default {
  id: "adr-desktop-protection",
  async server(context) {
    return {
      config: async config => {
        if (!contextServer) return;
        const command = [contextServer.command, ...contextServer.args];
        config.mcp ??= {};
        const existing = config.mcp[serverName];
        if (existing && JSON.stringify(existing.command) !== JSON.stringify(command)) {
          console.error("ADR was not registered: its MCP name is already in use.");
          return;
        }
        config.mcp[serverName] ??= { type: "local", command, enabled: true };
      },
      "tool.execute.before": async (input, output) => {
        const result = await check(event(input.tool, output.args, input.sessionID, context.directory), "pre");
        if (result.permissionDecision === "deny") throw new Error(result.permissionDecisionReason || unavailable);
      },
      "tool.execute.after": async (input, output) => {
        const result = await check(event(input.tool, input.args, input.sessionID, context.directory, output), "post");
        if (result.blocked) {
          // Replace the entire result, including metadata/attachments, not just visible text.
          for (const key of Object.keys(output)) delete output[key];
          Object.assign(output, { title: "ADR withheld a result", output: result.message, metadata: {} });
        }
      },
    };
  },
  async setup(context) {
    async function toolEvent(input, result) {
      // A V2 plugin instance can receive events for other session locations.
      // Resolve the actual session; never substitute the plugin's working directory.
      const session = await context.session.get({ sessionID: input.sessionID });
      return event(input.tool, input.input, input.sessionID, session.location?.directory, result);
    }
    await context.tool.hook("execute.before", async input => {
      let request;
      try { request = await toolEvent(input); } catch { throw new Error(unavailable); }
      const result = await check(request, "pre");
      if (result.permissionDecision === "deny") throw new Error(result.permissionDecisionReason || unavailable);
    });
    await context.tool.hook("execute.after", async input => {
      let result = blocked;
      try {
        result = await check(await toolEvent(input, input.status === "error" ?
          { error: { ...input.error, message: input.error?.message || "" } } : input.result), "post");
      } catch {}
      if (result.blocked) {
        if (input.status === "error") input.error = new Error(result.message);
        else input.result = { content: result.message };
      }
    });
    if (contextServer) {
      if (typeof context.mcp?.transform !== "function") {
        console.error("ADR Context requires an opencode version with the MCP registry transform API.");
        return;
      }
      await context.mcp.transform(registry => {
        const command = [contextServer.command, ...contextServer.args];
        const existing = registry.get(serverName);
        if (existing && JSON.stringify(existing.command) !== JSON.stringify(command)) {
          console.error("ADR was not registered: its MCP name is already in use.");
          return;
        }
        if (!existing) registry.set(serverName, { type: "local", command, disabled: false });
      });
    }
  },
};
