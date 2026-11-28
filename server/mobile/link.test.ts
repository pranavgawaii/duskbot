import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_MOBILE_RELAY, parseMobileLink, type MobilePairingResponse, type MobileRedeemResponse } from "../../shared/mobile-link.ts";
import type { RequestAuth } from "../request-auth.ts";
import { SessionRegistry } from "../sessions.ts";
import { createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, type KeyObject } from "node:crypto";
import { PUSH_PREVIEW_SEAL } from "../../shared/phone-activity.ts";

import { createMobileLink, mobileLookupRelay, PUSH_GRACE_MS, pushPreview, typedCodeRelay } from "./link.ts";
import { PRESENCE_OVERDUE_MS } from "./presence.ts";
import { lookupKeys, openLookup } from "./lookup.ts";
import type { PushMessage, PushTarget } from "./push.ts";

const owner: RequestAuth = { kind: "loopback", scopes: ["admin", "client"] };
const service: RequestAuth = { kind: "loopback", scopes: ["client"], trust: "service" };
const fakeReq = (body: unknown, headers: Record<string, string> = {}) => ({ headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.9", ...headers }, socket: { remoteAddress: "127.0.0.1" }, body } as unknown as IncomingMessage & { body: unknown });

function fakeRes() {
  const out = { status: 0, body: undefined as unknown, headers: {} as Record<string, string>, closed: false };
  const res = { setHeader: (name: string, value: string) => { out.headers[name] = value; }, once: () => res, writableEnded: false, destroyed: false } as unknown as ServerResponse;
  return { res, out };
}
const json = (res: ServerResponse, status: number, body: unknown) => { const own = res as unknown as { _out?: { status: number; body: unknown } }; own._out = { status, body }; };
const readBody = async (req: IncomingMessage) => (req as IncomingMessage & { body: unknown }).body;

let dir: string, sessions: SessionRegistry, lookups: Array<{ url: string; body: { id: string; sealed: string } }>, sent: Array<{ target: PushTarget; message: PushMessage }>;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "dusk-mobile-"));
  sessions = new SessionRegistry({ file: join(dir, "sessions.json") });
  lookups = [];
  sent = [];
});
afterEach(() => { sessions.close(); rmSync(dir, { recursive: true, force: true }); });

function openPreview(key: KeyObject, sealed: string): string {
  const raw = Buffer.from(sealed, "base64url");
  const shared = diffieHellman({ privateKey: key, publicKey: createPublicKey({ key: { kty: "OKP", crv: "X25519", x: raw.subarray(0, 32).toString("base64url") }, format: "jwk" }) });
  const decipher = createDecipheriv("aes-256-gcm", Buffer.from(hkdfSync("sha256", shared, PUSH_PREVIEW_SEAL.salt, PUSH_PREVIEW_SEAL.info, 32)), raw.subarray(32, 44));
  decipher.setAuthTag(raw.subarray(raw.length - 16));
  return Buffer.concat([decipher.update(raw.subarray(44, raw.length - 16)), decipher.final()]).toString("utf8");
}

function link(extra: Partial<Parameters<typeof createMobileLink>[0]> = {}) {
  return createMobileLink({
    dataDir: dir, sessions,
    workspace: () => ({ name: "Test box", environmentId: "env-1", kind: "server" }),
    publicOrigin: () => "https://box.example.com",
    refusal: () => null,
    lookupRelay: "http://relay.test",
    fetch: (async (url: string, init: RequestInit) => { lookups.push({ url, body: JSON.parse(String(init.body)) }); return new Response("{}", { status: 201 }); }) as typeof fetch,
    push: { configured: ["apns"], send: async (target, message) => { sent.push({ target, message }); return "sent"; } },
    log: () => {},
    ...extra,
  });
}

async function call(mobile: ReturnType<typeof link>, auth: RequestAuth, method: string, path: string, body: unknown = {}) {
  const { res } = fakeRes();
  const handled = await mobile.route({ req: fakeReq(body), res, path, method, auth, json, readBody });
  return { handled, ...(res as unknown as { _out: { status: number; body: any } })._out };
}
async function redeem(mobile: ReturnType<typeof link>, body: unknown) {
  const { res } = fakeRes();
  await mobile.publicRoute(fakeReq(body), res, "/api/mobile/redeem", "POST", json, readBody);
  return (res as unknown as { _out: { status: number; body: any } })._out;
}

describe("mobile link", () => {
  it("pairs a phone from a QR payload, lists it, and revoking ends its session", async () => {
    const mobile = link();
    const paired = await call(mobile, owner, "POST", "/api/mobile/pairing", { companion: [{ url: "http://192.168.1.4:8810", kind: "lan", priority: 30 }] });
    expect(paired.status).toBe(200);
    const answer = paired.body as MobilePairingResponse;
    const payload = parseMobileLink(answer.link)!;
    expect(payload.via.map((one) => one.kind)).toEqual(["https", "companion"]);
    expect(payload.workspace).toEqual({ name: "Test box", environmentId: "env-1", kind: "server" });
    expect(answer.code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    // the typed code finds the same payload, sealed so the relay cannot read it
    expect(lookups[0].url).toBe("http://relay.test/v1/lookups");
    expect(lookups[0].body.id).toBe(lookupKeys(answer.code!).id);
    expect(openLookup(answer.code!, lookups[0].body.sealed)).toEqual(payload);

    const redeemed = await redeem(mobile, { secret: payload.grant.secret, attemptId: "attempt-0001", device: { name: "Sid's iPhone", platform: "ios" } });
    expect(redeemed.status).toBe(200);
    const phone = redeemed.body as MobileRedeemResponse;
    expect(phone.token).toMatch(/^dusk_sess_/);
    expect(phone.scopes.sort()).toEqual(["admin", "client"]);
    expect(sessions.authenticate(phone.token)?.label).toBe("Sid's iPhone");
    // a lost answer is fetched again with the same attempt, never a second device
    expect((await redeem(mobile, { secret: payload.grant.secret, attemptId: "attempt-0001", device: { name: "x", platform: "ios" } })).body.token).toBe(phone.token);
    expect((await redeem(mobile, { secret: payload.grant.secret, attemptId: "attempt-0002", device: { name: "x", platform: "ios" } })).status).toBe(410);

    const listed = await call(mobile, owner, "GET", "/api/mobile/devices");
    expect(listed.body.devices).toHaveLength(1);
    expect(JSON.stringify(readFileSync(join(dir, "mobile-devices.json"), "utf8"))).not.toContain(phone.token);
    expect((await call(mobile, owner, "DELETE", `/api/mobile/devices/${phone.device.id}`)).status).toBe(200);
    expect(sessions.authenticate(phone.token)).toBeNull();
    expect((await call(mobile, owner, "GET", "/api/mobile/devices")).body.devices).toHaveLength(0);
  });

  it("tells a paired phone the ways to this workspace now, and nobody else", async () => {
    let origin = "https://box.example.com", endpoints: Array<{ url: string; kind: "lan" | "bonjour"; priority: number }> | null = [{ url: "http://192.168.1.4:8810", kind: "lan", priority: 30 }];
    const mobile = link({ publicOrigin: () => origin, companion: async () => endpoints });
    const payload = parseMobileLink((await call(mobile, owner, "POST", "/api/mobile/pairing")).body.link)!;
    const phone = (await redeem(mobile, { secret: payload.grant.secret, attemptId: "attempt-routes", device: { name: "p", platform: "ios" } })).body as MobileRedeemResponse;
    const auth: RequestAuth = { kind: "session", session: sessions.authenticate(phone.token)!, via: "bearer", scopes: phone.scopes };
    expect((await call(mobile, auth, "GET", "/api/mobile/routes")).body).toEqual({ https: [{ kind: "https", url: "https://box.example.com" }], companion: [{ kind: "companion", url: "http://192.168.1.4:8810", net: "lan", priority: 30 }] });
    origin = "https://new.example.com";
    endpoints = [{ url: "http://192.168.1.9:8810", kind: "lan", priority: 30 }, { url: "http://mac.local:8810", kind: "bonjour", priority: 300 }];
    const now = (await call(mobile, auth, "GET", "/api/mobile/routes")).body;
    expect(now.https).toEqual([{ kind: "https", url: "https://new.example.com" }]);
    expect(now.companion.map((one: { url: string }) => one.url)).toEqual(["http://192.168.1.9:8810", "http://mac.local:8810"]);
    endpoints = null;
    expect((await call(mobile, auth, "GET", "/api/mobile/routes")).body.companion).toBeNull();
    const client = sessions.issue({ label: "c", scopes: ["client"] });
    expect((await call(mobile, { kind: "session", session: sessions.authenticate(client.token)!, via: "bearer", scopes: ["client"] }, "GET", "/api/mobile/routes")).status).toBe(404);
  });

  it("only the owner or an admin pairs, and a service caller or client session cannot", async () => {
    const mobile = link();
    expect((await call(mobile, service, "POST", "/api/mobile/pairing")).status).toBe(403);
    const client = sessions.issue({ label: "c", scopes: ["client"] });
    const auth: RequestAuth = { kind: "session", session: sessions.authenticate(client.token)!, via: "bearer", scopes: ["client"] };
    expect((await call(mobile, auth, "POST", "/api/mobile/pairing")).status).toBe(403);
    expect((await call(link({ refusal: () => "no" }), owner, "POST", "/api/mobile/pairing")).status).toBe(403);
  });

  it("tells a phone a used or expired grant expired, and a cloud's phone to sign in, so the app never says refused", async () => {
    const mobile = link();
    const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
    const wrong = await redeem(mobile, { secret: `${answer.payload.grant.secret.slice(0, -1)}x`, attemptId: "attempt-0101", device: { name: "p", platform: "ios" } });
    expect(wrong).toMatchObject({ status: 410, body: { code: "expired" } });
    const cloud = link({ refusal: () => "Phones sign in to this workspace through its own sign-in." });
    expect(await call(cloud, owner, "POST", "/api/mobile/pairing")).toMatchObject({ status: 403, body: { code: "sign_in_instead" } });
    expect(await redeem(cloud, { secret: answer.payload.grant.secret, attemptId: "attempt-0102", device: { name: "p", platform: "ios" } })).toMatchObject({ status: 403, body: { code: "sign_in_instead" } });
  });

  it("refuses a grant nothing could reach", async () => {
    const mobile = link({ publicOrigin: () => null, lookupRelay: null });
    expect((await call(mobile, owner, "POST", "/api/mobile/pairing")).status).toBe(409);
  });

  it("serves relay channels to the link agent and hands a phone its own channel", async () => {
    const mobile = link({ publicOrigin: () => null });
    const phonePub = generateKeyPairSync("x25519").publicKey.export({ format: "jwk" }).x!;
    const agent = { base: "https://link.test", tunnel: "abcdefghij", pub: "A".repeat(43) };
    // the agent's sync: answered at once the first time, then held until something changes
    const first = await call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 0, wait: 0 });
    expect(first.body).toEqual({ rev: 1, channels: [] });
    expect((await call(mobile, service, "POST", "/api/mobile/relay/sync", { ...agent, applied: 0 })).status).toBe(403);

    const syncing = call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 1, wait: 5 });
    const pairing = call(mobile, owner, "POST", "/api/mobile/pairing");
    const held = await syncing;
    expect(held.body.channels).toEqual([expect.objectContaining({ kind: "grant", verifier: expect.stringMatching(/^[0-9a-f]{64}$/), key: expect.any(String) })]);
    // the agent registered it with the relay: the pairing answer now carries the relay transport
    void call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: held.body.rev, wait: 5 });
    const answer = (await pairing).body as MobilePairingResponse;
    const relay = answer.payload.via.find((one) => one.kind === "relay")!;
    expect(relay).toMatchObject({ kind: "relay", base: "https://link.test", channel: held.body.channels[0].id });
    expect(answer.payload.workspace.kind).toBe("vps");

    const redeeming = redeem(mobile, { secret: answer.payload.grant.secret, attemptId: "attempt-0003", device: { name: "Pixel", platform: "android" }, relay: { pub: phonePub, verifier: "c".repeat(64) } });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const next = await call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: held.body.rev, wait: 0 });
    const device = next.body.channels.find((one: { kind: string }) => one.kind === "device");
    expect(device).toMatchObject({ pub: phonePub, verifier: "c".repeat(64) });
    void call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: next.body.rev, wait: 0 });
    const phone = (await redeeming).body as MobileRedeemResponse;
    expect(phone.relay).toEqual({ base: "https://link.test", channel: device.id, agentPub: agent.pub });

    // revoking a session anywhere (the session list in settings) drops the phone and its channel
    sessions.revoke(sessions.authenticate(phone.token)!.id);
    const after = await call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: next.body.rev, wait: 0 });
    expect(after.body.channels.some((one: { kind: string }) => one.kind === "device")).toBe(false);
  });

  it("posts a typed code where the phone looks it up, even when the server's link agent lives on another dusk bot node", async () => {
    const mobile = link({ publicOrigin: () => null, lookupRelay: null });
    const agent = { base: "https://link-in.dusk.bot", tunnel: "abcdefghij", pub: "A".repeat(43) };
    await call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 0, wait: 0 });
    const syncing = call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 1, wait: 5 });
    const pairing = call(mobile, owner, "POST", "/api/mobile/pairing");
    const held = await syncing;
    void call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: held.body.rev, wait: 5 });
    const answer = (await pairing).body as MobilePairingResponse;
    expect(answer.payload.via.find((one) => one.kind === "relay")).toMatchObject({ base: "https://link-in.dusk.bot" });
    expect(answer.code).toEqual(expect.any(String));
    expect(lookups.map((one) => one.url)).toEqual([`${DEFAULT_MOBILE_RELAY}/v1/lookups`]);
    expect(typedCodeRelay("https://link.example.org")).toBe("https://link.example.org");
  });

  it("leaves the link agent's https address out of a code while it answers 5xx or nothing, so a phone pairs over the relay", async () => {
    const agent = { base: "https://link.test", tunnel: "abcdefghij", pub: "A".repeat(43), origin: "https://box.trycloudflare.com" };
    for (const [health, kinds] of [[530, ["relay"]], ["down", ["relay"]], [200, ["https", "relay"]]] as const) {
      const checked: string[] = [];
      const mobile = link({
        publicOrigin: () => null,
        fetch: (async (url: string) => {
          if (!url.endsWith("/api/health")) return new Response("{}", { status: 201 });
          checked.push(url);
          if (health === "down") throw new TypeError("fetch failed");
          return new Response("", { status: health });
        }) as typeof fetch,
      });
      await call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 0, wait: 0 });
      const syncing = call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 1, wait: 5 });
      const pairing = call(mobile, owner, "POST", "/api/mobile/pairing");
      const held = await syncing;
      void call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: held.body.rev, wait: 5 });
      const answer = (await pairing).body as MobilePairingResponse;
      expect(answer.payload.via.map((one) => one.kind)).toEqual(kinds);
      expect(checked).toEqual(["https://box.trycloudflare.com/api/health"]);
    }
  });

  it("a desktop with its own relay hub puts the relay and its wi-fi routes in one code and stays a computer", async () => {
    const mobile = link({ publicOrigin: () => null, workspace: () => ({ name: "My Mac", environmentId: "env-mac", kind: "mac" }) });
    const agent = { base: "https://link.test", tunnel: "abcdefghij", pub: "A".repeat(43) };
    const companionPhone = { ...owner, companionDevice: "phone-1" } as RequestAuth;
    expect((await call(mobile, companionPhone, "POST", "/api/mobile/relay/sync", { ...agent, applied: 0, wait: 0 })).status).toBe(403);
    await call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 0, wait: 0 });
    const syncing = call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 1, wait: 5 });
    const pairing = call(mobile, owner, "POST", "/api/mobile/pairing", { companion: [{ url: "http://192.168.1.20:8810", kind: "lan", priority: 200 }] });
    const held = await syncing;
    void call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: held.body.rev, wait: 5 });
    const answer = (await pairing).body as MobilePairingResponse;
    expect(answer.payload.workspace.kind).toBe("mac");
    expect(answer.payload.via.map((one) => one.kind)).toEqual(["relay", "companion"]);
  });

  it("gives a phone paired before the relay was up its own relay channel when it asks, without pairing again", async () => {
    const mobile = link();
    const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
    const phone = (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId: "attempt-0401", device: { name: "Pixel", platform: "android" } })).body as MobileRedeemResponse;
    expect(phone.relay).toBeUndefined();
    const auth: RequestAuth = { kind: "session", session: sessions.authenticate(phone.token)!, via: "bearer", scopes: phone.scopes };
    expect((await call(mobile, auth, "GET", "/api/mobile/routes")).body).not.toHaveProperty("relay");

    // the relay comes up later (the computer signed in, the link agent installed)
    const agent = { base: "https://link.test", tunnel: "abcdefghij", pub: "A".repeat(43) };
    const first = await call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: 0, wait: 0 });
    expect((await call(mobile, auth, "GET", "/api/mobile/routes")).body.relay).toBeNull();
    const phonePub = generateKeyPairSync("x25519").publicKey.export({ format: "jwk" }).x!;
    const asking = call(mobile, auth, "POST", "/api/mobile/relay", { pub: phonePub, verifier: "d".repeat(64) });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const next = await call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: first.body.rev, wait: 0 });
    const channel = next.body.channels.find((one: { kind: string }) => one.kind === "device");
    expect(channel).toMatchObject({ pub: phonePub, verifier: "d".repeat(64) });
    void call(mobile, owner, "POST", "/api/mobile/relay/sync", { ...agent, applied: next.body.rev, wait: 0 });
    expect((await asking)).toMatchObject({ status: 200, body: { base: "https://link.test", channel: channel.id, agentPub: agent.pub } });
    expect((await call(mobile, auth, "GET", "/api/mobile/routes")).body.relay).toEqual({ base: "https://link.test", channel: channel.id, agentPub: agent.pub });
    expect((await call(mobile, auth, "POST", "/api/mobile/relay", { pub: "nope", verifier: "d".repeat(64) })).status).toBe(400);
  });

  it("keeps a paired phone's session until the phone is removed, used or not", async () => {
    let clock = Date.now();
    sessions.close();
    sessions = new SessionRegistry({ file: join(dir, "sessions.json"), now: () => clock });
    const mobile = link();
    const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
    const phone = (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId: "attempt-0402", device: { name: "p", platform: "ios" } })).body as MobileRedeemResponse;
    clock += 400 * 24 * 60 * 60_000;
    expect(sessions.authenticate(phone.token)).not.toBeNull();
    expect((await call(mobile, owner, "GET", "/api/mobile/devices")).body.devices).toHaveLength(1);
  });

  it("refuses a relay key no agreement can use", async () => {
    const mobile = link();
    const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
    const refused = await redeem(mobile, { secret: answer.payload.grant.secret, attemptId: "attempt-0009", device: { name: "p", platform: "ios" }, relay: { pub: Buffer.alloc(32).toString("base64url"), verifier: "c".repeat(64) } });
    expect(refused.status).toBe(400);
  });

  it("registers a phone for push and fans notifications out without their text", async () => {
    vi.useFakeTimers();
    const mobile = link();
    const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
    const phone = (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId: "attempt-0004", device: { name: "p", platform: "ios" } })).body as MobileRedeemResponse;
    const auth: RequestAuth = { kind: "session", session: sessions.authenticate(phone.token)!, via: "bearer", scopes: phone.scopes };
    expect((await call(mobile, owner, "PUT", "/api/mobile/push", { service: "apns", token: "abcdef0123456789" })).status).toBe(403);
    expect((await call(mobile, auth, "PUT", "/api/mobile/push", { service: "apns", token: "abcdef0123456789", environment: "sandbox" })).body).toEqual({ ok: true, delivering: true });
    await mobile.notify({ id: "n1", at: 1, read: false, kind: "mention", botId: "b1", botName: "Nova", threadId: "t1", title: "Nova", body: "secret text" });
    await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
    expect(sent).toEqual([{ target: { service: "apns", token: "abcdef0123456789", environment: "sandbox" }, message: { id: "n1", kind: "mention", title: "Nova", botId: "b1", botName: "Nova", threadId: "t1", environmentId: "env-1" } }]);
    await mobile.notify({ id: "n1", at: 1, read: false, kind: "mention", botId: "b1", botName: "Nova", threadId: "t1", title: "Nova", body: "again" });
    await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
    expect(sent).toHaveLength(1);
    vi.useRealTimers();
  });

  it("seals each push's preview to the phone's own key, counts the unread for the badge, and has Android draw it", async () => {
    vi.useFakeTimers();
    let unread = 3;
    const mobile = link({ unreadCount: () => unread });
    const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
    const phone = (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId: "attempt-0201", device: { name: "p", platform: "android" } })).body as MobileRedeemResponse;
    const auth: RequestAuth = { kind: "session", session: sessions.authenticate(phone.token)!, via: "bearer", scopes: phone.scopes };
    const keys = generateKeyPairSync("x25519");
    const previewKey = keys.publicKey.export({ format: "jwk" }).x!;
    expect((await call(mobile, auth, "PUT", "/api/mobile/push", { service: "fcm", token: "fcm-token-0123456789", previewKey: Buffer.alloc(32).toString("base64url") })).status).toBe(400);
    expect((await call(mobile, auth, "PUT", "/api/mobile/push", { service: "fcm", token: "fcm-token-0123456789", previewKey, draws: true })).status).toBe(200);
    await mobile.notify({ id: "n7", at: 1, read: false, kind: "done", botId: "b1", botName: "Nova", threadId: "t1", title: "Nova finished", body: "The flights are booked for Friday" });
    await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
    vi.useRealTimers();
    const [{ target, message }] = sent;
    expect(target).toEqual({ service: "fcm", token: "fcm-token-0123456789", draws: true });
    expect(message).toMatchObject({ id: "n7", botName: "Nova", threadId: "t1", environmentId: "env-1", badge: 3 });
    expect(JSON.stringify(message).includes("flights")).toBe(false);
    expect(openPreview(keys.privateKey, message.sealed!)).toBe("The flights are booked for Friday");
    unread = 0;
  });

  it("shows what a bot said, and for an ask what it is with its detail", () => {
    expect(pushPreview({ kind: "done", title: "Nova finished", body: "All  set\nfor Friday" })).toBe("All set for Friday");
    expect(pushPreview({ kind: "approval", title: "Nova needs your OK", body: "Send the invoice" })).toBe("Nova needs your OK: Send the invoice");
    expect(pushPreview({ kind: "done", title: "Nova", body: "x".repeat(300) })).toHaveLength(240);
  });

  it("a phone paired again with its install id replaces the pairing it made before, push or not", async () => {
    const mobile = link();
    const pairOnce = async (attemptId: string, install: string) => {
      const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
      return (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId, device: { name: "p", platform: "android", install } })).body as MobileRedeemResponse;
    };
    const first = await pairOnce("attempt-0301", "0b5e6a52-6a0e-4f7e-9d0c-1f2e3d4c5b6a");
    const other = await pairOnce("attempt-0302", "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d");
    const again = await pairOnce("attempt-0303", "0b5e6a52-6a0e-4f7e-9d0c-1f2e3d4c5b6a");
    const listed = (await call(mobile, owner, "GET", "/api/mobile/devices")).body.devices.map((one: { id: string }) => one.id);
    expect(listed).toEqual([other.device.id, again.device.id]);
    expect(sessions.authenticate(first.token)).toBeNull();
    expect(sessions.authenticate(other.token)).not.toBeNull();
    const odd = await pairOnce("attempt-0304", "not an id");
    expect((await call(mobile, owner, "GET", "/api/mobile/devices")).body.devices).toHaveLength(3);
    expect(sessions.authenticate(odd.token)).not.toBeNull();
  });

  it("a phone paired again takes its push token from the pairing it replaced, which is removed, so each notification arrives once", async () => {
    vi.useFakeTimers();
    const mobile = link();
    const pairOnce = async (attemptId: string) => {
      const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
      const phone = (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId, device: { name: "p", platform: "ios" } })).body as MobileRedeemResponse;
      const auth: RequestAuth = { kind: "session", session: sessions.authenticate(phone.token)!, via: "bearer", scopes: phone.scopes };
      expect((await call(mobile, auth, "PUT", "/api/mobile/push", { service: "apns", token: "abcdef0123456789" })).status).toBe(200);
      return { phone, auth };
    };
    const first = await pairOnce("attempt-0201");
    const again = await pairOnce("attempt-0202");
    expect((await call(mobile, owner, "GET", "/api/mobile/devices")).body.devices.map((one: { id: string }) => one.id)).toEqual([again.phone.device.id]);
    expect(sessions.authenticate(first.phone.token)).toBeNull();
    await mobile.notify({ id: "n1", at: 1, read: false, kind: "mention", botId: "b1", botName: "Nova", threadId: "t1", title: "Nova", body: "x" });
    await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
    expect(sent).toHaveLength(1);
    vi.useRealTimers();
  });

  it("registers an iPhone's Live Activity and push-to-start tokens, and an approval's ask id travels with its push", async () => {
    const mobile = link();
    const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
    const phone = (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId: "attempt-0005", device: { name: "p", platform: "ios" } })).body as MobileRedeemResponse;
    const auth: RequestAuth = { kind: "session", session: sessions.authenticate(phone.token)!, via: "bearer", scopes: phone.scopes };
    expect((await call(mobile, owner, "PUT", "/api/mobile/activity", { threadId: "t1", token: "ab".repeat(16) })).status).toBe(403);
    expect((await call(mobile, auth, "PUT", "/api/mobile/activity", { threadId: "t1", token: "not hex" })).status).toBe(400);
    expect((await call(mobile, auth, "PUT", "/api/mobile/activity", { threadId: "t1", token: "ab".repeat(16) })).status).toBe(200);
    expect(mobile.activities("t1")).toHaveLength(1);
    expect((await call(mobile, auth, "DELETE", "/api/mobile/activity", { threadId: "t1" })).status).toBe(200);
    expect(mobile.activities("t1")).toHaveLength(0);
    expect((await call(mobile, auth, "PUT", "/api/mobile/activity-start", { token: "cd".repeat(16), environment: "sandbox" })).status).toBe(200);
    expect(mobile.state().devices[0]!.activityStart).toMatchObject({ token: "cd".repeat(16), environment: "sandbox" });
    await call(mobile, auth, "PUT", "/api/mobile/push", { service: "apns", token: "abcdef0123456789" });
    vi.useFakeTimers();
    await mobile.notify({ id: "n2", at: 1, read: false, kind: "approval", botId: "b1", botName: "Nova", threadId: "t1", title: "Nova", body: "x", requestId: "req-1" });
    await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
    vi.useRealTimers();
    expect(sent.at(-1)?.message).toMatchObject({ kind: "approval", requestId: "req-1" });
  });

  describe("away phones", () => {
    afterEach(() => { vi.useRealTimers(); });
    async function pushPhone(mobile: ReturnType<typeof link>, attempt: string) {
      const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
      const phone = (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId: attempt, device: { name: "p", platform: "ios" } })).body as MobileRedeemResponse;
      const auth: RequestAuth = { kind: "session", session: sessions.authenticate(phone.token)!, via: "bearer", scopes: phone.scopes };
      await call(mobile, auth, "PUT", "/api/mobile/push", { service: "apns", token: "abcdef0123456789" });
      return auth;
    }
    const note = (id: string, threadId = "t1") => ({ id, at: 1, read: false, kind: "mention" as const, botId: "b1", botName: "Nova", threadId, title: "Nova", body: "x" });

    it("never pushes a conversation the open app is showing, and pushes the others after the grace", async () => {
      vi.useFakeTimers();
      const mobile = link();
      const auth = await pushPhone(mobile, "attempt-0101");
      expect((await call(mobile, auth, "PUT", "/api/mobile/presence", { away: false, threadId: "t1" })).status).toBe(200);
      await mobile.notify(note("n1"));
      await mobile.notify(note("n2", "t2"));
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS - 1);
      expect(sent).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(1);
      // the open app on another chat gets the push, so iOS shows its own banner
      expect(sent.map((one) => one.message.id)).toEqual(["n2"]);
    });

    it("drops a waiting push once the phone opens that conversation", async () => {
      vi.useFakeTimers();
      const mobile = link();
      const auth = await pushPhone(mobile, "attempt-0102");
      await call(mobile, auth, "PUT", "/api/mobile/presence", { away: false, threadId: null });
      await mobile.notify(note("n1"));
      await vi.advanceTimersByTimeAsync(1_000);
      await call(mobile, auth, "PUT", "/api/mobile/presence", { away: false, threadId: "t1" });
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      expect(sent).toHaveLength(0);
    });

    it("cancels a waiting push when the notification is read on any device", async () => {
      vi.useFakeTimers();
      const read = new Set<string>();
      const mobile = link({ isRead: (id) => read.has(id) });
      await pushPhone(mobile, "attempt-0103");
      await mobile.notify(note("n1"));
      await mobile.notify(note("n2", "t2"));
      await mobile.notify(note("n3", "t3"));
      mobile.read(["n1"]);
      // read somewhere without a frame reaching here: the push still checks before it leaves
      read.add("n2");
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      expect(sent.map((one) => one.message.id)).toEqual(["n3"]);
    });

    it("clears a conversation read anywhere on each Android phone that was shown it, even with its app closed", async () => {
      vi.useFakeTimers();
      const mobile = link({ unreadCount: () => 1, push: { configured: ["fcm"], send: async (target, message) => { sent.push({ target, message }); return "sent"; } } });
      const android = async (attempt: string, token: string) => {
        const answer = (await call(mobile, owner, "POST", "/api/mobile/pairing")).body as MobilePairingResponse;
        const phone = (await redeem(mobile, { secret: answer.payload.grant.secret, attemptId: attempt, device: { name: "p", platform: "android" } })).body as MobileRedeemResponse;
        const auth: RequestAuth = { kind: "session", session: sessions.authenticate(phone.token)!, via: "bearer", scopes: phone.scopes };
        await call(mobile, auth, "PUT", "/api/mobile/push", { service: "fcm", token, draws: true });
      };
      await android("attempt-0111", "fcm-token-phone-a");
      await android("attempt-0112", "fcm-token-phone-b");
      await mobile.notify(note("n1"));
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      await mobile.notify(note("n2"));
      await mobile.notify(note("n3", "t2"));
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      sent.length = 0;
      // part of a conversation read: its notification still has news
      mobile.read(["n1"]);
      expect(sent).toHaveLength(0);
      mobile.read(["n2"]);
      expect(sent.map((one) => [one.target.token, one.message.kind, one.message.threadId, one.message.id])).toEqual([
        ["fcm-token-phone-a", "read", "t1", "n2"], ["fcm-token-phone-b", "read", "t1", "n2"],
      ]);
      expect(sent[0].target.draws).toBe(true);
      expect(sent[0].message).toMatchObject({ botName: "Nova", badge: 1 });
      mobile.read(["n1", "n2"]);
      expect(sent).toHaveLength(2);
    });

    it("never sends a read to a phone whose app does not draw its own notifications", async () => {
      vi.useFakeTimers();
      const mobile = link();
      await pushPhone(mobile, "attempt-0113");
      await mobile.notify(note("n1"));
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      mobile.read(["n1"]);
      expect(sent.map((one) => one.message.kind)).toEqual(["mention"]);
    });

    it("sends one push per conversation, the newest, when several land within the grace", async () => {
      vi.useFakeTimers();
      const mobile = link();
      await pushPhone(mobile, "attempt-0104");
      await mobile.notify(note("n1"));
      await mobile.notify(note("n2"));
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      expect(sent.map((one) => one.message.id)).toEqual(["n2"]);
    });

    it("counts an app that stopped checking in as away, even on the conversation it last showed", async () => {
      vi.useFakeTimers();
      const mobile = link();
      const auth = await pushPhone(mobile, "attempt-0105");
      await call(mobile, auth, "PUT", "/api/mobile/presence", { away: false, threadId: "t1" });
      await vi.advanceTimersByTimeAsync(64_000);
      await mobile.notify(note("n2"));
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      expect(sent.map((one) => one.message.id)).toEqual(["n2"]);
      await call(mobile, auth, "PUT", "/api/mobile/presence", { away: true, threadId: "t1" });
      await mobile.notify(note("n3"));
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      expect(sent.map((one) => one.message.id)).toEqual(["n2", "n3"]);
    });

    it("pushes what the open chat showed when the phone then goes quiet, as one suspended before its away got out", async () => {
      vi.useFakeTimers();
      const mobile = link();
      const auth = await pushPhone(mobile, "attempt-0106");
      await call(mobile, auth, "PUT", "/api/mobile/presence", { away: false, threadId: "t1" });
      await vi.advanceTimersByTimeAsync(10_000);
      await mobile.notify(note("n1"));
      await vi.advanceTimersByTimeAsync(PRESENCE_OVERDUE_MS - 10_000 - 1);
      expect(sent).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(1);
      expect(sent.map((one) => one.message.id)).toEqual(["n1"]);
    });

    it("never pushes what the open chat showed once the phone checks in again", async () => {
      vi.useFakeTimers();
      const mobile = link();
      const auth = await pushPhone(mobile, "attempt-0107");
      await call(mobile, auth, "PUT", "/api/mobile/presence", { away: false, threadId: "t1" });
      await mobile.notify(note("n1"));
      await vi.advanceTimersByTimeAsync(20_000);
      await call(mobile, auth, "PUT", "/api/mobile/presence", { away: true, threadId: null });
      await vi.advanceTimersByTimeAsync(PRESENCE_OVERDUE_MS);
      expect(sent).toHaveLength(0);
    });

    it("pushes after the grace to a phone that never reported, and tries a failed push again at 10 s and 60 s", async () => {
      vi.useFakeTimers();
      const outcomes = ["failed", "failed", "sent"] as const;
      const tries: string[] = [];
      const mobile = link({ push: { configured: ["apns"], send: async (_target, message) => { tries.push(message.id); return outcomes[tries.length - 1] ?? "sent"; } } });
      await pushPhone(mobile, "attempt-0104");
      await mobile.notify(note("n1"));
      expect(tries).toEqual([]);
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS);
      expect(tries).toEqual(["n1"]);
      await vi.advanceTimersByTimeAsync(10_000);
      expect(tries).toEqual(["n1", "n1"]);
      await vi.advanceTimersByTimeAsync(60_000);
      expect(tries).toEqual(["n1", "n1", "n1"]);
      await vi.advanceTimersByTimeAsync(120_000);
      expect(tries).toHaveLength(3);
    });

    it("keeps trying a push the service could not take for five minutes, past a relay's bad patch", async () => {
      vi.useFakeTimers();
      const outcomes = ["failed", "failed", "failed", "sent"] as const;
      const tries: number[] = [];
      const mobile = link({ push: { configured: ["apns"], send: async () => { tries.push(Date.now()); return outcomes[tries.length - 1] ?? "sent"; } } });
      await pushPhone(mobile, "attempt-0106");
      await mobile.notify(note("n1"));
      await vi.advanceTimersByTimeAsync(PUSH_GRACE_MS + 10_000 + 60_000);
      expect(tries).toHaveLength(3);
      await vi.advanceTimersByTimeAsync(300_000);
      expect(tries).toHaveLength(4);
    });

    it("takes presence only from a paired phone", async () => {
      const mobile = link();
      const auth = await pushPhone(mobile, "attempt-0105");
      expect((await call(mobile, owner, "PUT", "/api/mobile/presence", { away: false })).status).toBe(403);
      expect((await call(mobile, auth, "PUT", "/api/mobile/presence", { away: "no" })).status).toBe(400);
      expect((await call(mobile, auth, "PUT", "/api/mobile/presence", { away: false, threadId: "no spaces" })).status).toBe(400);
      expect((await call(mobile, auth, "PUT", "/api/mobile/presence", { away: false, threadId: 7 })).status).toBe(400);
    });
  });

  it("reads the typed-code relay from the environment", () => {
    expect(mobileLookupRelay({})).toBeNull();
    // the desktop app types codes through the public relay unless told not to
    expect(mobileLookupRelay({}, true)).toBe("https://link.dusk.bot");
    expect(mobileLookupRelay({ DUSK_MOBILE_RELAY: "none" }, true)).toBeNull();
    expect(mobileLookupRelay({ DUSK_MOBILE_RELAY: "default" })).toBe("https://link.dusk.bot");
    expect(mobileLookupRelay({ DUSK_MOBILE_RELAY: "http://127.0.0.1:9" })).toBe("http://127.0.0.1:9");
  });
});
