import { generateKeyPairSync } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createLinkService } from "../src/app.mjs";
import { activityMessage, createPushRelay, pushCategory, pushMessage } from "../src/push-relay.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const files = {
  "/keys/account.json": JSON.stringify({ project_id: "fixture-project", client_email: "push@fixture.example", token_uri: "https://oauth.example/token", private_key: rsa.privateKey.export({ format: "pem", type: "pkcs8" }).toString() }),
  "/keys/apns.p8": ec.privateKey.export({ format: "pem", type: "pkcs8" }),
};
const readFile = (path) => { if (!(path in files)) throw new Error("missing"); return files[path]; };
const message = { id: "n1", kind: "mention", botId: "b1", botName: "Nova", threadId: "t1", title: "should not travel" };
let server, base, dir, calls, fcmStatus;

function fakeFetch() {
  return async (url, init) => {
    calls.push({ url: String(url), body: init?.body });
    if (String(url) === "https://oauth.example/token") return new Response(JSON.stringify({ access_token: "access", expires_in: 3600 }), { status: 200 });
    return new Response(JSON.stringify(fcmStatus === 404 ? { error: { status: "NOT_FOUND" } } : {}), { status: fcmStatus });
  };
}

async function start(push) {
  const service = createLinkService({ base: "http://link.test", dataDir: dir, scriptPath: join(root, "install.sh"), agentPath: join(root, "agent.mjs"), trustProxy: false, push });
  server = createServer((req, res) => void service.handler(req, res));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
}
const post = (body) => fetch(`${base}/v1/push`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "omb-push-relay-")); calls = []; fcmStatus = 200; });
afterEach(async () => { if (server) await new Promise((resolve) => server.close(resolve)); server = undefined; rmSync(dir, { recursive: true, force: true }); });

describe("push relay", () => {
  it("says which services it delivers and refuses one it has no keys for", async () => {
    await start(createPushRelay({ env: {}, fetch: fakeFetch(), readFile }));
    expect(await (await fetch(`${base}/v1/push`)).json()).toEqual({ services: [] });
    const answer = await post({ service: "fcm", token: "fixture-token", message });
    expect(answer.status).toBe(503);
    expect((await answer.json()).code).toBe("not_configured");
  });

  it("sends an FCM push with the bot's name and ids only, and reports a dead token", async () => {
    await start(createPushRelay({ env: { DUSK_FCM_SERVICE_ACCOUNT_FILE: "/keys/account.json", DUSK_FCM_HOST: "https://fcm.example" }, fetch: fakeFetch(), readFile }));
    expect(await (await post({ service: "fcm", token: "fixture-token", message })).json()).toEqual({ outcome: "sent" });
    const sent = calls.find((one) => one.url.startsWith("https://fcm.example"));
    expect(sent.url).toBe("https://fcm.example/v1/projects/fixture-project/messages:send");
    expect(JSON.parse(sent.body).message).toEqual({
      token: "fixture-token", notification: { title: "Nova", body: "New message" },
      data: { id: "n1", kind: "mention", botId: "b1", threadId: "t1" }, android: { priority: "high", notification: { channel_id: "messages", tag: "t1" } },
    });
    expect(sent.body).not.toContain("should not travel");
    fcmStatus = 404;
    expect(await (await post({ service: "fcm", token: "fixture-token", message })).json()).toEqual({ outcome: "gone" });
  });

  it("sends data only to an app that draws its own notification, with its sealed preview and count", async () => {
    await start(createPushRelay({ env: { DUSK_FCM_SERVICE_ACCOUNT_FILE: "/keys/account.json", DUSK_FCM_HOST: "https://fcm.example" }, fetch: fakeFetch(), readFile }));
    const sealed = "s".repeat(120);
    expect(await (await post({ service: "fcm", token: "fixture-token", draws: true, message: { ...message, environmentId: "env-cloud", sealed, badge: 4 } })).json()).toEqual({ outcome: "sent" });
    const sent = JSON.parse(calls.find((one) => one.url.startsWith("https://fcm.example")).body).message;
    expect(sent).toEqual({
      token: "fixture-token", android: { priority: "high", ttl: "2419200s" },
      data: { dusk: "1", id: "n1", kind: "mention", botId: "b1", threadId: "t1", environmentId: "env-cloud", sealed, botName: "Nova", badge: "4" },
    });
    expect(await (await post({ service: "fcm", token: "fixture-token", draws: true, message: { ...message, kind: "read" } })).json()).toEqual({ outcome: "sent" });
    expect(JSON.parse(calls.filter((one) => one.url.startsWith("https://fcm.example")).at(-1).body).message.android).toEqual({ priority: "normal", ttl: "2419200s" });
    expect((await post({ service: "fcm", token: "fixture-token", message: { ...message, sealed: "not sealed!" } })).status).toBe(400);
    expect((await post({ service: "fcm", token: "fixture-token", message: { ...message, badge: -1 } })).status).toBe(400);
    expect((await post({ service: "fcm", token: "fixture-token", message: { ...message, environmentId: "bad/place" } })).status).toBe(400);
  });

  it("sends an APNs alert to the sandbox when asked", async () => {
    const requests = [];
    const http2Connect = (origin) => {
      const session = Object.assign(new EventEmitter(), { closed: false, destroyed: false, unref() {}, close() {}, destroy() {} });
      session.request = (headers) => {
        const stream = Object.assign(new EventEmitter(), { setEncoding() {}, close() {} });
        stream.end = (body) => { requests.push({ origin, headers, body: JSON.parse(body) }); queueMicrotask(() => { stream.emit("response", { ":status": 200 }); stream.emit("end"); }); };
        return stream;
      };
      return session;
    };
    await start(createPushRelay({ env: { DUSK_APNS_KEY_FILE: "/keys/apns.p8", DUSK_APNS_KEY_ID: "key", DUSK_APNS_TEAM_ID: "team", DUSK_APNS_TOPIC: "com.example.omb" }, http2Connect, readFile }));
    expect(await (await post({ service: "apns", token: "abcdef0123456789", environment: "sandbox", message })).json()).toEqual({ outcome: "sent" });
    expect(requests[0].origin).toBe("https://api.sandbox.push.apple.com");
    expect(requests[0].headers[":path"]).toBe("/3/device/abcdef0123456789");
    expect(requests[0].headers["apns-topic"]).toBe("com.example.omb");
    expect(requests[0].headers["apns-collapse-id"]).toBeUndefined();
    expect(requests[0].body).toEqual({
      aps: { alert: { title: "Nova", body: "New message" }, sound: "default", "thread-id": "t1", "mutable-content": 1, category: "dusk.message" },
      dusk: { id: "n1", kind: "mention", botId: "b1", threadId: "t1" },
    });
  });

  it("drops an APNs connection that stopped answering and sends on a new one, so later pushes do not wait on it", async () => {
    const sessions = [];
    const http2Connect = () => {
      const session = Object.assign(new EventEmitter(), { closed: false, destroyed: false, unref() {}, close() {}, destroy() { session.destroyed = true; } });
      const answers = sessions.length > 0;
      session.request = () => {
        const stream = Object.assign(new EventEmitter(), { setEncoding() {}, close() {} });
        stream.end = () => { if (answers) queueMicrotask(() => { stream.emit("response", { ":status": 200 }); stream.emit("end"); }); };
        return stream;
      };
      sessions.push(session);
      return session;
    };
    const relay = createPushRelay({ env: { DUSK_APNS_KEY_FILE: "/keys/apns.p8", DUSK_APNS_KEY_ID: "key", DUSK_APNS_TEAM_ID: "team", DUSK_APNS_TOPIC: "com.example.omb" }, http2Connect, readFile, serviceTimeoutMs: 50 });
    await start(relay);
    expect(await (await post({ service: "apns", token: "abcdef0123456789", message })).json()).toEqual({ outcome: "sent" });
    expect(sessions).toHaveLength(2);
    expect(sessions[0].destroyed).toBe(true);
    expect(await (await post({ service: "apns", token: "abcdef0123456789", message })).json()).toEqual({ outcome: "sent" });
    expect(sessions).toHaveLength(2);
  });

  it("refuses bad input and limits pushes per device token", async () => {
    await start(createPushRelay({ env: { DUSK_FCM_SERVICE_ACCOUNT_FILE: "/keys/account.json", DUSK_FCM_HOST: "https://fcm.example" }, fetch: fakeFetch(), readFile }));
    expect((await post({ service: "sms", token: "fixture-token", message })).status).toBe(400);
    expect((await post({ service: "fcm", token: "bad token!", message })).status).toBe(400);
    expect((await post({ service: "fcm", token: "fixture-token", message: { ...message, botName: "" } })).status).toBe(400);
    for (let i = 0; i < 60; i++) expect((await post({ service: "fcm", token: "fixture-token", message })).status).toBe(200);
    expect((await post({ service: "fcm", token: "fixture-token", message })).status).toBe(429);
    expect((await post({ service: "fcm", token: "other-token", message })).status).toBe(200);
  });

  it("cleans the bot's name for a lock screen", () => {
    expect(pushMessage({ ...message, botName: ` ${"N".repeat(100)}\u0007 ` })?.botName).toBe("N".repeat(80));
    expect(pushMessage({ ...message, groupId: "g1" })).toEqual({ id: "n1", kind: "mention", botId: "b1", botName: "Nova", threadId: "t1", groupId: "g1" });
    expect(pushMessage({ ...message, environmentId: "env-cloud" })).toMatchObject({ environmentId: "env-cloud" });
    expect(pushMessage({ ...message, threadId: "a/b" })).toBeNull();
  });

  it("carries an ask's id and picks the buttons a push gets", () => {
    expect(pushMessage({ ...message, kind: "approval", requestId: "req-1" })?.requestId).toBe("req-1");
    expect(pushMessage({ ...message, requestId: "a b" })).toBeNull();
    expect(pushCategory({ kind: "approval", requestId: "r" })).toBe("dusk.approval");
    expect(pushCategory({ kind: "approval" })).toBeUndefined();
    expect(pushCategory({ kind: "question" })).toBe("dusk.question");
    expect(pushCategory({ kind: "done" })).toBe("dusk.message");
    expect(pushCategory({ kind: "done", groupId: "g" })).toBeUndefined();
    expect(pushCategory({ kind: "spend" })).toBeUndefined();
  });

  const at = 1_800_000_000;
  const activity = { event: "update", timestamp: at, priority: 5, state: { phase: "working", step: "web", steps: 3, startedAt: at - 60 } };

  it("passes only the activity fields the widget knows", () => {
    expect(activityMessage(activity)).toEqual(activity);
    expect(activityMessage({ ...activity, state: { ...activity.state, line: "the reply in the clear" } })).toEqual(activity);
    expect(activityMessage({ ...activity, state: { ...activity.state, step: "Searching for my bank login" } })).toBeNull();
    expect(activityMessage({ ...activity, state: { ...activity.state, phase: "anything" } })).toBeNull();
    expect(activityMessage({ ...activity, state: { ...activity.state, sealed: "not sealed text" } })).toBeNull();
    expect(activityMessage({ ...activity, priority: 1 })).toBeNull();
    const start = { ...activity, event: "start", priority: 10, attributes: { botId: "b1", botName: "Nova", threadId: "t1", color: "blue", body: "kit", extra: "dropped" } };
    expect(activityMessage(start)?.attributes).toEqual({ botId: "b1", botName: "Nova", threadId: "t1", color: "blue", body: "kit" });
    expect(activityMessage({ ...start, attributes: { ...start.attributes, botName: "" } })).toBeNull();
  });

  it("sends a Live Activity push on the liveactivity topic, and refuses one for FCM", async () => {
    const requests = [];
    const http2Connect = () => {
      const session = Object.assign(new EventEmitter(), { closed: false, destroyed: false, unref() {}, close() {}, destroy() {} });
      session.request = (headers) => {
        const stream = Object.assign(new EventEmitter(), { setEncoding() {}, close() {} });
        stream.end = (body) => { requests.push({ headers, body: JSON.parse(body) }); queueMicrotask(() => { stream.emit("response", { ":status": 200 }); stream.emit("end"); }); };
        return stream;
      };
      return session;
    };
    await start(createPushRelay({ env: { DUSK_APNS_KEY_FILE: "/keys/apns.p8", DUSK_APNS_KEY_ID: "key", DUSK_APNS_TEAM_ID: "team", DUSK_APNS_TOPIC: "com.example.omb" }, http2Connect, readFile }));
    const end = { event: "end", timestamp: at, dismissAt: at + 240, priority: 10, state: { phase: "done", steps: 3, startedAt: at - 60 } };
    expect(await (await post({ service: "apns", token: "abcdef0123456789", activity: end })).json()).toEqual({ outcome: "sent" });
    expect(requests[0].headers["apns-topic"]).toBe("com.example.omb.push-type.liveactivity");
    expect(requests[0].headers["apns-push-type"]).toBe("liveactivity");
    expect(requests[0].headers["apns-priority"]).toBe("10");
    expect(requests[0].body).toEqual({ aps: { timestamp: at, event: "end", "content-state": end.state, "dismissal-date": at + 240 } });
    expect((await post({ service: "fcm", token: "abcdef0123456789", activity: end })).status).toBe(400);
  });
});
