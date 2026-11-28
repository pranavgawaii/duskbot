// phone push for workspaces that hold no APNs or FCM keys of their own. the phone app's keys live here, once, instead of
// on every person's computer and server.
//
// what it sees: the device token, apns or fcm, the bot's name, the ids a tap opens (notification, bot, thread, room,
// ask) and the app icon's count. never a title, a message or anything a person wrote in the clear: a push's preview
// line comes sealed to a key only that phone holds. it keeps nothing and logs no token. a Live Activity push carries
// only a fixed vocabulary (phase, step kind, counts, times) and, for the end, the reply's first line sealed the same way.
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect, constants } from "node:http2";

const SERVICES = new Set(["apns", "fcm"]);
const TOKEN = /^[\w:.-]{8,4096}$/;
const ID = /^[\w:.-]{1,128}$/;
const KIND = /^[a-z][a-z0-9_-]{0,31}$/;
const PER_TOKEN_PER_MINUTE = 60;
const PER_IP_PER_MINUTE = 600;
/** one APNs or FCM request; under the workspace's own wait (server/mobile/push.ts RELAY_TIMEOUT_MS) even tried twice */
export const SERVICE_TIMEOUT_MS = 6_000;
const PREVIEW = /^[A-Za-z0-9_-]{80,2000}$/;

function jwt(header, claims, key) {
  const input = [header, claims].map((part) => Buffer.from(JSON.stringify(part)).toString("base64url")).join(".");
  return `${input}.${sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}

const cleanName = (value) => typeof value === "string" ? [...value].filter((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127).join("").trim().slice(0, 80) : "";
const optionalId = (value) => value === undefined || (typeof value === "string" && ID.test(value));

/** the message a workspace asks to push, or null; the bot's name is cut to what a lock screen shows */
export function pushMessage(value) {
  if (!value || typeof value !== "object") return null;
  const { id, kind, botId, threadId, environmentId, groupId, requestId, sealed, badge } = value;
  if (![id, botId, threadId].every((one) => typeof one === "string" && ID.test(one)) || typeof kind !== "string" || !KIND.test(kind)) return null;
  if (!optionalId(environmentId) || !optionalId(groupId) || !optionalId(requestId)) return null;
  if (sealed !== undefined && (typeof sealed !== "string" || !PREVIEW.test(sealed))) return null;
  if (badge !== undefined && !(Number.isSafeInteger(badge) && badge >= 0 && badge <= 9999)) return null;
  const botName = cleanName(value.botName);
  if (!botName) return null;
  return {
    id, kind, botId, botName, threadId, ...(environmentId !== undefined ? { environmentId } : {}),
    ...(groupId !== undefined ? { groupId } : {}), ...(requestId !== undefined ? { requestId } : {}),
    ...(sealed !== undefined ? { sealed } : {}), ...(badge !== undefined ? { badge } : {}),
  };
}

const idsOf = ({ botName: _name, badge: _badge, ...ids }) => ids;

/** the APNs alert: stacked under its conversation, opened by the app's extension (mutable-content) to show the preview */
export function alertBody(message) {
  const category = pushCategory(message);
  return {
    aps: {
      alert: { title: message.botName, body: "New message" }, sound: "default", "thread-id": message.threadId, "mutable-content": 1,
      ...(message.badge !== undefined ? { badge: message.badge } : {}), ...(category ? { category } : {}),
    },
    dusk: idsOf(message),
  };
}

/** the FCM message: data only for an app that draws its own (Android hands it over while the app is closed), else the
 * system-drawn notification an older app needs */
export function fcmBody(token, message, draws) {
  if (draws) {
    return {
      // FCM deprioritizes an app whose high priority messages show nothing, and a read only takes a notification away
      token, android: { priority: message.kind === "read" ? "normal" : "high", ttl: "2419200s" },
      data: { dusk: "1", ...idsOf(message), botName: message.botName, ...(message.badge !== undefined ? { badge: String(message.badge) } : {}) },
    };
  }
  return { token, notification: { title: message.botName, body: "New message" }, data: idsOf(message), android: { priority: "high", notification: { channel_id: "messages", tag: message.threadId } } };
}

const REPLY_KINDS = new Set(["done", "mention", "brief", "wait", "delegation-settled"]);

/** the notification's buttons, as the app registers them */
export function pushCategory({ kind, requestId, groupId }) {
  if (kind === "approval") return requestId ? "dusk.approval" : undefined;
  if (kind === "question") return "dusk.question";
  if (REPLY_KINDS.has(kind) && !groupId) return "dusk.message";
  return undefined;
}

const PHASES = new Set(["working", "needs-you", "done", "stopped"]);
const STEPS = new Set(["write", "edit", "command", "web", "read", "fetch", "search", "tool"]);
const EVENTS = new Set(["update", "end", "start"]);
const SEALED = /^[A-Za-z0-9_-]{80,700}$/;
const COLOR = /^[a-z]{1,16}$/;
const BODY = /^[a-z]{1,16}$/;
const seconds = (value) => Number.isSafeInteger(value) && value > 1_500_000_000 && value < 10_000_000_000;

/** a Live Activity push a workspace asks for, or null: only the fields and values the phone's widget knows */
export function activityMessage(value) {
  if (!value || typeof value !== "object" || !EVENTS.has(value.event) || !seconds(value.timestamp) || (value.priority !== 5 && value.priority !== 10)) return null;
  const s = value.state;
  if (!s || typeof s !== "object" || !PHASES.has(s.phase) || !seconds(s.startedAt) || !Number.isSafeInteger(s.steps) || s.steps < 0 || s.steps > 100_000) return null;
  if (s.step !== undefined && !STEPS.has(s.step)) return null;
  if (s.sealed !== undefined && (typeof s.sealed !== "string" || !SEALED.test(s.sealed))) return null;
  if (s.ask !== undefined && (!s.ask || (s.ask.kind !== "approve" && s.ask.kind !== "answer") || typeof s.ask.requestId !== "string" || !ID.test(s.ask.requestId))) return null;
  const state = {
    phase: s.phase, steps: s.steps, startedAt: s.startedAt, ...(s.step ? { step: s.step } : {}),
    ...(s.ask ? { ask: { kind: s.ask.kind, requestId: s.ask.requestId } } : {}), ...(s.sealed ? { sealed: s.sealed } : {}),
  };
  const out = { event: value.event, state, timestamp: value.timestamp, priority: value.priority };
  if (value.event === "end" && value.dismissAt !== undefined) {
    if (!seconds(value.dismissAt)) return null;
    out.dismissAt = value.dismissAt;
  }
  if (value.event === "start") {
    const a = value.attributes;
    if (!a || typeof a !== "object" || ![a.botId, a.threadId].every((one) => typeof one === "string" && ID.test(one)) || !optionalId(a.groupId)) return null;
    if (typeof a.color !== "string" || !COLOR.test(a.color) || typeof a.body !== "string" || !BODY.test(a.body)) return null;
    const botName = cleanName(a.botName);
    if (!botName) return null;
    out.attributes = { botId: a.botId, botName, threadId: a.threadId, ...(a.groupId !== undefined ? { groupId: a.groupId } : {}), color: a.color, body: a.body };
  }
  return out;
}

/** the APNs body of a checked activity push */
export function activityBody(push) {
  return {
    aps: {
      timestamp: push.timestamp, event: push.event, "content-state": push.state,
      ...(push.event === "end" && push.dismissAt ? { "dismissal-date": push.dismissAt } : {}),
      ...(push.event === "start" && push.attributes ? {
        "attributes-type": "DuskTurnAttributes", attributes: push.attributes, alert: { title: push.attributes.botName, body: "Waiting for you" },
      } : {}),
    },
  };
}

export function createPushRelay({ env = process.env, now = Date.now, fetch: fetchImpl = fetch, http2Connect = connect, readFile = readFileSync, log = () => {}, serviceTimeoutMs = SERVICE_TIMEOUT_MS } = {}) {
  const services = [];
  let apns, fcm;
  const { DUSK_APNS_KEY_FILE: keyFile, DUSK_APNS_KEY_ID: keyId, DUSK_APNS_TEAM_ID: teamId, DUSK_APNS_TOPIC: topic } = env;
  if (keyFile || keyId || teamId || topic) {
    try {
      if (!keyFile || !keyId || !teamId || !topic) throw new Error("incomplete");
      const key = createPrivateKey(readFile(keyFile));
      if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error("invalid key");
      apns = { key, keyId, teamId, topic };
      services.push("apns");
    } catch {
      log("push relay: could not load APNs credentials; APNs is off");
    }
  }
  if (env.DUSK_FCM_SERVICE_ACCOUNT_FILE) {
    try {
      const account = JSON.parse(readFile(env.DUSK_FCM_SERVICE_ACCOUNT_FILE).toString());
      if (![account.project_id, account.client_email, account.private_key, account.token_uri].every((one) => typeof one === "string" && one)) throw new Error("invalid account");
      const key = createPrivateKey(account.private_key);
      if (key.asymmetricKeyType !== "rsa") throw new Error("invalid key");
      fcm = { key, projectId: account.project_id, email: account.client_email, tokenUri: account.token_uri };
      services.push("fcm");
    } catch {
      log("push relay: could not load FCM credentials; FCM is off");
    }
  }

  let providerToken;
  const sessions = new Map();
  function apnsSession(origin) {
    const known = sessions.get(origin);
    if (known && !known.closed && !known.destroyed) return known;
    const session = http2Connect(origin);
    sessions.set(origin, session);
    const discard = () => { if (sessions.get(origin) === session) sessions.delete(origin); };
    session.on("error", () => { discard(); session.destroy(); });
    session.on("close", discard);
    session.on("goaway", () => { discard(); session.close(); });
    session.unref();
    return session;
  }

  function sendApns(token, environment, headers, payload, again = true) {
    if (!providerToken || now() - providerToken.createdAt >= 50 * 60_000) {
      providerToken = { value: jwt({ alg: "ES256", kid: apns.keyId }, { iss: apns.teamId, iat: Math.floor(now() / 1000) }, apns.key), createdAt: now() };
    }
    const origin = env.DUSK_APNS_HOST ?? (environment === "sandbox" ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com");
    const session = apnsSession(origin);
    return new Promise((resolve) => {
      const request = session.request({
        ":method": "POST", ":path": `/3/device/${token}`, authorization: `bearer ${providerToken.value}`, ...headers,
      });
      let status = 0, body = "", settled = false;
      const finish = (outcome) => { if (settled) return; settled = true; clearTimeout(timer); resolve(outcome); };
      // a connection a NAT or APNs dropped without a word answers nothing, and every push after would wait on it too:
      // it goes, and the push is tried once more on a new one
      const timer = setTimeout(() => {
        request.close(constants.NGHTTP2_CANCEL);
        if (sessions.get(origin) === session) sessions.delete(origin);
        session.destroy();
        log(`push relay: APNs did not answer in ${serviceTimeoutMs / 1000} s; ${again ? "trying again on a new connection" : "gave up"}`);
        if (again) { settled = true; resolve(sendApns(token, environment, headers, payload, false)); } else finish("failed");
      }, serviceTimeoutMs);
      request.setEncoding("utf8");
      request.on("response", (headers) => { status = Number(headers[":status"]); });
      request.on("data", (chunk) => { body += chunk; });
      request.on("error", () => finish("failed"));
      request.on("close", () => finish("failed"));
      request.on("end", () => {
        if (status === 200) return finish("sent");
        if (status === 410) return finish("gone");
        let reason;
        try { reason = JSON.parse(body).reason; } catch {}
        finish(status === 400 && (reason === "BadDeviceToken" || reason === "DeviceTokenNotForTopic") ? "gone" : "failed");
      });
      request.end(JSON.stringify(payload));
    });
  }

  function sendAlert(token, environment, message) {
    return sendApns(token, environment, { "apns-topic": apns.topic, "apns-push-type": "alert", "apns-priority": "10" }, alertBody(message));
  }

  function sendActivity(token, environment, activity) {
    return sendApns(token, environment, { "apns-topic": `${apns.topic}.push-type.liveactivity`, "apns-push-type": "liveactivity", "apns-priority": String(activity.priority) }, activityBody(activity));
  }

  let accessToken, exchange;
  async function fcmToken() {
    if (accessToken && now() < accessToken.expiresAt - 5 * 60_000) return accessToken.value;
    exchange ??= (async () => {
      const at = now(), iat = Math.floor(at / 1000);
      const assertion = jwt({ alg: "RS256", typ: "JWT" }, { iss: fcm.email, scope: "https://www.googleapis.com/auth/firebase.messaging", aud: fcm.tokenUri, iat, exp: iat + 3600 }, fcm.key);
      const response = await fetchImpl(fcm.tokenUri, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }), signal: AbortSignal.timeout(serviceTimeoutMs),
      });
      const answer = response.ok ? await response.json() : null;
      if (typeof answer?.access_token !== "string" || !answer.access_token || !(answer.expires_in > 0)) throw new Error("token exchange failed");
      accessToken = { value: answer.access_token, expiresAt: at + answer.expires_in * 1000 };
      return accessToken.value;
    })().finally(() => { exchange = undefined; });
    return exchange;
  }

  async function sendFcm(token, message, draws) {
    const access = await fcmToken();
    const response = await fetchImpl(`${env.DUSK_FCM_HOST ?? "https://fcm.googleapis.com"}/v1/projects/${encodeURIComponent(fcm.projectId)}/messages:send`, {
      method: "POST", headers: { authorization: `Bearer ${access}`, "content-type": "application/json" },
      body: JSON.stringify({ message: fcmBody(token, message, draws) }),
      signal: AbortSignal.timeout(serviceTimeoutMs),
    });
    if (response.status === 200) return "sent";
    if (response.status === 404) return "gone";
    const error = (await response.json().catch(() => null))?.error;
    if (Array.isArray(error?.details) && error.details.some((detail) => detail?.errorCode === "UNREGISTERED")) return "gone";
    if (response.status === 400 && error?.status === "INVALID_ARGUMENT" && /registration[\s_-]*token/i.test(String(error.message ?? ""))) return "gone";
    return "failed";
  }

  const recent = new Map();
  function allowed(key, limit) {
    const since = now() - 60_000;
    const list = (recent.get(key) ?? []).filter((at) => at > since);
    if (list.length >= limit) { recent.set(key, list); return false; }
    list.push(now());
    recent.set(key, list);
    if (recent.size > 50_000) for (const [one, times] of recent) if (!times.some((at) => at > since)) recent.delete(one);
    return true;
  }

  return {
    services,
    /** GET /v1/push says which services it delivers; POST /v1/push {service, token, environment?, draws?, message | activity}
     * sends one (an activity is APNs only; `draws`: FCM to an app that draws its own notification) */
    async route(req, res, { method, readJson, send, fail, ip }) {
      if (method === "GET") return send(res, 200, { services });
      if (method !== "POST") return fail(res, 405, "method not allowed");
      const body = await readJson(req, 16_384);
      const service = SERVICES.has(body?.service) ? body.service : null;
      const token = typeof body?.token === "string" && TOKEN.test(body.token) ? body.token : null;
      const environment = body?.environment === "sandbox" ? "sandbox" : "production";
      const draws = service === "fcm" && body?.draws === true;
      const activity = body?.activity !== undefined && service === "apns" ? activityMessage(body.activity) : null;
      const message = activity ? null : pushMessage(body?.message);
      if (!service || !token || (!message && !activity)) return fail(res, 400, "service, token and message are required", "invalid");
      if (!services.includes(service)) return fail(res, 503, `this relay has no ${service === "apns" ? "APNs" : "FCM"} keys`, "not_configured");
      if (!allowed(`ip:${ip}`, PER_IP_PER_MINUTE) || !allowed(`token:${token}`, PER_TOKEN_PER_MINUTE)) return fail(res, 429, "too many pushes", "rate_limited");
      let outcome;
      try { outcome = activity ? await sendActivity(token, environment, activity) : service === "apns" ? await sendAlert(token, environment, message) : await sendFcm(token, message, draws); }
      catch { outcome = "failed"; }
      if (outcome === "failed") log(`push relay: a ${service === "apns" ? "APNs" : "FCM"} push failed`);
      return send(res, 200, { outcome });
    },
  };
}
