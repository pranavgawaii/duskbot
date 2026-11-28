import { createPrivateKey, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect, constants, type ClientHttp2Session } from "node:http2";
import type { PushService } from "../../shared/mobile-link.ts";
import { pushCategory, TURN_ACTIVITY_TYPE, type TurnActivityAttributes, type TurnActivityState } from "../../shared/phone-activity.ts";

/** What a push carries: never a message body in the clear. The preview line goes sealed to the phone's own key, so only
 * that phone shows what was said; the relay, Apple and Google see who wrote. */
export interface PushMessage {
  id: string;
  kind: string;
  title: string;
  botId: string;
  botName: string;
  threadId: string;
  environmentId?: string;
  groupId?: string;
  /** an approval's or question's ask, so the notification's buttons answer that one */
  requestId?: string;
  /** the preview line sealed to the phone's push key (PUSH_PREVIEW_SEAL) */
  sealed?: string;
  /** the app icon's count: unread notifications */
  badge?: number;
}

/** One Live Activity push: an update, the end, or (push-to-start) the start of one. Never carries `line`. */
export interface ActivityPush {
  event: "update" | "end" | "start";
  state: Omit<TurnActivityState, "line">;
  /** epoch seconds; the phone drops a push older than the one it showed */
  timestamp: number;
  /** end only: when the lock screen lets it go, epoch seconds */
  dismissAt?: number;
  /** start only */
  attributes?: TurnActivityAttributes;
  /** 10 for what the person must see now (an ask, the end), 5 for a step */
  priority: 5 | 10;
}

export interface PushTarget {
  service: PushService;
  token: string;
  environment?: "sandbox" | "production";
  /** FCM: the app draws the notification itself, so the push is data-only and wakes it while it is closed */
  draws?: boolean;
}

/** `gone`: the service says the token is dead, so the phone's registration is dropped. */
export type PushOutcome = "sent" | "gone" | "failed" | "skipped";

export interface PushSender {
  configured: readonly PushService[];
  /** whether a push for this service leaves this server at all: its own keys, or a push relay */
  delivers?(service: PushService): boolean;
  send(target: PushTarget, message: PushMessage): Promise<PushOutcome>;
  /** APNs only; `target.token` is the activity's own token, or the push-to-start one */
  sendActivity?(target: PushTarget, push: ActivityPush): Promise<PushOutcome>;
  /** where pushes leave from now: this server's own keys, and the relay with the services it says it has (null when it
   * could not be asked) */
  status?(): Promise<PushStatus>;
}

export interface PushStatus { own: PushService[]; relay: string | null; relayServices: PushService[] | null }

/** The APNs body of a Live Activity push. */
export function activityApnsBody(push: ActivityPush): object {
  return {
    aps: {
      timestamp: push.timestamp, event: push.event, "content-state": push.state,
      ...(push.event === "end" && push.dismissAt ? { "dismissal-date": push.dismissAt } : {}),
      ...(push.event === "start" && push.attributes ? {
        "attributes-type": TURN_ACTIVITY_TYPE, attributes: push.attributes,
        alert: { title: push.attributes.botName, body: "Waiting for you" },
      } : {}),
    },
  };
}

/** One APNs or FCM request; a dead connection is dropped and the push tried once more on a new one. */
export const SERVICE_TIMEOUT_MS = 6_000;
/** The relay's answer: above its two tries of SERVICE_TIMEOUT_MS, so a slow push is not abandoned while it goes. */
export const RELAY_TIMEOUT_MS = 20_000;

/** How long a relay that said it has no keys for a service is left alone before it is asked again. */
export const RELAY_RECHECK_MS = 30 * 60_000;

/** DUSK_PUSH_RELAY: where a server with no APNs or FCM keys of its own sends pushes ("off" for nowhere); unset, `fallback` */
export function pushRelayBase(env: NodeJS.ProcessEnv, fallback: string | null): string | null {
  const value = env.DUSK_PUSH_RELAY?.trim().replace(/\/+$/, "");
  if (value === "off") return null;
  if (value) return /^https?:\/\/[^/\s]+$/.test(value) ? value : null;
  return fallback;
}

function jwt(header: object, claims: object, key: KeyObject): string {
  const input = [header, claims].map((part) => Buffer.from(JSON.stringify(part)).toString("base64url")).join(".");
  const signature = sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
  return `${input}.${signature.toString("base64url")}`;
}

function messageData(message: PushMessage): Record<string, string> {
  return {
    kind: message.kind, botId: message.botId, threadId: message.threadId, id: message.id,
    ...(message.environmentId !== undefined ? { environmentId: message.environmentId } : {}),
    ...(message.groupId !== undefined ? { groupId: message.groupId } : {}),
    ...(message.requestId !== undefined ? { requestId: message.requestId } : {}),
    ...(message.sealed !== undefined ? { sealed: message.sealed } : {}),
  };
}

const badgeOf = (message: PushMessage) => message.badge !== undefined && Number.isSafeInteger(message.badge) && message.badge >= 0 ? Math.min(message.badge, 9999) : undefined;

/** Each push stacks under its conversation (`thread-id`); the app's extension opens the sealed preview (`mutable-content`). */
export function apnsAlertBody(message: PushMessage): object {
  const category = pushCategory(message);
  const badge = badgeOf(message);
  return {
    aps: {
      alert: { title: message.botName, body: "New message" }, sound: "default", "thread-id": message.threadId, "mutable-content": 1,
      ...(badge !== undefined ? { badge } : {}), ...(category ? { category } : {}),
    },
    dusk: messageData(message),
  };
}

/** A data-only push to an Android app that draws its own notifications: this conversation was read, up to `id`. */
export const READ_KIND = "read";

/** The FCM message. An app that draws its own gets data only, which Android hands it even while it is closed; an older
 * app gets the system-drawn notification. */
export function fcmMessage(target: PushTarget, message: PushMessage): object {
  if (target.draws) {
    const badge = badgeOf(message);
    return {
      token: target.token,
      data: { dusk: "1", ...messageData(message), botName: message.botName, ...(badge !== undefined ? { badge: String(badge) } : {}) },
      // FCM deprioritizes an app whose high priority messages show nothing, and a read only takes a notification away
      android: { priority: message.kind === READ_KIND ? "normal" : "high", ttl: "2419200s" },
    };
  }
  return {
    token: target.token, notification: { title: message.botName, body: "New message" }, data: messageData(message),
    android: { priority: "high", notification: { channel_id: "messages", tag: message.threadId } },
  };
}

export function createPushSender(env: NodeJS.ProcessEnv = process.env, deps: {
  http2Connect?: typeof connect;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  readFile?: (path: string) => string | Buffer;
  log?: (message: string) => void;
  /** the push relay, asked at each send: it holds the app's own APNs and FCM keys */
  relay?: () => string | null;
  /** SERVICE_TIMEOUT_MS */
  serviceTimeoutMs?: number;
} = {}): PushSender {
  const serviceTimeoutMs = deps.serviceTimeoutMs ?? SERVICE_TIMEOUT_MS;
  const readFile = deps.readFile ?? readFileSync;
  const now = deps.now ?? Date.now;
  const log = deps.log ?? console.warn;
  const http2Connect = deps.http2Connect ?? connect;
  const fetch = deps.fetch ?? globalThis.fetch;
  const configured: PushService[] = [];
  let apns: { key: KeyObject; keyId: string; teamId: string; topic: string } | undefined;
  let fcm: { key: KeyObject; projectId: string; email: string; tokenUri: string } | undefined;

  const { DUSK_APNS_KEY_FILE: keyFile, DUSK_APNS_KEY_ID: keyId, DUSK_APNS_TEAM_ID: teamId, DUSK_APNS_TOPIC: topic } = env;
  if (keyFile || keyId || teamId || topic) {
    try {
      if (!keyFile || !keyId || !teamId || !topic) throw new Error("incomplete credentials");
      const key = createPrivateKey(readFile(keyFile));
      if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error("invalid key");
      apns = { key, keyId, teamId, topic };
      configured.push("apns");
    } catch {
      log("mobile push: could not load APNs credentials; APNs is disabled");
    }
  }
  if (env.DUSK_FCM_SERVICE_ACCOUNT_FILE) {
    try {
      const account = JSON.parse(readFile(env.DUSK_FCM_SERVICE_ACCOUNT_FILE).toString());
      if (![account.project_id, account.client_email, account.private_key, account.token_uri].every((value) => typeof value === "string" && value.length > 0)) throw new Error("invalid account");
      const key = createPrivateKey(account.private_key);
      if (key.asymmetricKeyType !== "rsa") throw new Error("invalid key");
      fcm = { key, projectId: account.project_id, email: account.client_email, tokenUri: account.token_uri };
      configured.push("fcm");
    } catch {
      log("mobile push: could not load FCM credentials; FCM is disabled");
    }
  }

  let providerToken: { value: string; createdAt: number } | undefined;
  let session: ClientHttp2Session | undefined;
  let sessionOrigin: string | undefined;
  function apnsSession(origin: string): ClientHttp2Session {
    if (session && sessionOrigin === origin && !session.closed && !session.destroyed) return session;
    session?.close();
    const current = http2Connect(origin);
    session = current;
    sessionOrigin = origin;
    const discard = () => { if (session === current) session = undefined; };
    current.on("error", () => { discard(); current.destroy(); });
    current.on("close", discard);
    current.on("goaway", () => { discard(); current.close(); });
    current.unref();
    return current;
  }

  async function sendApns(target: PushTarget, kind: { type: "alert" } | { type: "liveactivity"; priority: 5 | 10 }, payload: object, again = true): Promise<PushOutcome> {
    const credentials = apns!;
    const timestamp = now();
    if (!providerToken || timestamp - providerToken.createdAt >= 50 * 60_000) {
      providerToken = {
        value: jwt({ alg: "ES256", kid: credentials.keyId }, { iss: credentials.teamId, iat: Math.floor(timestamp / 1000) }, credentials.key),
        createdAt: timestamp,
      };
    }
    const origin = env.DUSK_APNS_HOST ?? (target.environment === "sandbox" ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com");
    const current = apnsSession(origin);
    return new Promise<PushOutcome>((resolve) => {
      const request = current.request({
        ":method": "POST", ":path": `/3/device/${target.token}`,
        authorization: `bearer ${providerToken!.value}`,
        ...(kind.type === "alert"
          ? { "apns-topic": credentials.topic, "apns-push-type": "alert", "apns-priority": "10" }
          : { "apns-topic": `${credentials.topic}.push-type.liveactivity`, "apns-push-type": "liveactivity", "apns-priority": String(kind.priority) }),
      });
      let status = 0;
      let body = "";
      let settled = false;
      const finish = (outcome: PushOutcome) => { if (settled) return; settled = true; clearTimeout(timer); resolve(outcome); };
      // a connection that went quiet (a NAT or APNs dropped it) answers nothing; it is dropped so the next push opens a new one
      const timer = setTimeout(() => {
        request.close(constants.NGHTTP2_CANCEL);
        if (session === current) session = undefined;
        current.destroy();
        if (again) { settled = true; resolve(sendApns(target, kind, payload, false)); } else finish("failed");
      }, serviceTimeoutMs);
      request.setEncoding("utf8");
      request.on("response", (headers) => { status = Number(headers[":status"]); });
      request.on("data", (chunk: string) => { body += chunk; });
      request.on("error", () => finish("failed"));
      request.on("close", () => finish("failed"));
      request.on("end", () => {
        if (status === 200) return finish("sent");
        if (status === 410) return finish("gone");
        let reason: unknown;
        try { reason = JSON.parse(body).reason; } catch {}
        finish(status === 400 && (reason === "BadDeviceToken" || reason === "DeviceTokenNotForTopic") ? "gone" : "failed");
      });
      request.end(JSON.stringify(payload));
    });
  }

  let accessToken: { value: string; expiresAt: number } | undefined;
  let tokenExchange: Promise<string> | undefined;
  async function fcmToken(): Promise<string> {
    if (accessToken && now() < accessToken.expiresAt - 5 * 60_000) return accessToken.value;
    if (tokenExchange) return tokenExchange;
    const credentials = fcm!;
    tokenExchange = (async () => {
      const timestamp = now();
      const iat = Math.floor(timestamp / 1000);
      const assertion = jwt({ alg: "RS256", typ: "JWT" }, {
        iss: credentials.email, scope: "https://www.googleapis.com/auth/firebase.messaging",
        aud: credentials.tokenUri, iat, exp: iat + 3600,
      }, credentials.key);
      const response = await fetch(credentials.tokenUri, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }),
        signal: AbortSignal.timeout(serviceTimeoutMs),
      });
      if (!response.ok) throw new Error("token exchange failed");
      const token = await response.json() as { access_token?: unknown; expires_in?: unknown } | null;
      if (!token || typeof token.access_token !== "string" || !token.access_token || typeof token.expires_in !== "number" || !Number.isFinite(token.expires_in) || token.expires_in <= 0) throw new Error("invalid token response");
      accessToken = { value: token.access_token, expiresAt: timestamp + token.expires_in * 1000 };
      return accessToken.value;
    })();
    try { return await tokenExchange; } finally { tokenExchange = undefined; }
  }

  async function sendFcm(target: PushTarget, message: PushMessage): Promise<PushOutcome> {
    const token = await fcmToken();
    const origin = env.DUSK_FCM_HOST ?? "https://fcm.googleapis.com";
    const response = await fetch(`${origin}/v1/projects/${encodeURIComponent(fcm!.projectId)}/messages:send`, {
      method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ message: fcmMessage(target, message) }),
      signal: AbortSignal.timeout(serviceTimeoutMs),
    });
    if (response.status === 200) return "sent";
    if (response.status === 404) return "gone";
    const result = await response.json() as { error?: { status?: string; message?: string; details?: unknown } } | null;
    const error = result?.error;
    if (Array.isArray(error?.details) && error.details.some((detail: { errorCode?: string }) => detail?.errorCode === "UNREGISTERED")) return "gone";
    if (response.status === 400 && error?.status === "INVALID_ARGUMENT" && typeof error.message === "string" && /registration[\s_-]*token/i.test(error.message)) return "gone";
    return "failed";
  }

  /** the relay sees the device token, the bot's name and the ids a tap opens; never a title or message text */
  async function sendRelay(base: string, target: PushTarget, what: { message: Omit<PushMessage, "title"> } | { activity: ActivityPush }): Promise<PushOutcome> {
    const response = await fetch(`${base}/v1/push`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ service: target.service, token: target.token, ...(target.environment ? { environment: target.environment } : {}), ...(target.draws ? { draws: true } : {}), ...what }),
      signal: AbortSignal.timeout(RELAY_TIMEOUT_MS),
    });
    const answer = await response.json().catch(() => null) as { outcome?: unknown; code?: unknown } | null;
    if (response.status === 503 && answer?.code === "not_configured") {
      lacking.set(`${base}\n${target.service}`, now());
      if (!told.has(target.service)) {
        told.add(target.service);
        log(target.service === "fcm"
          ? `mobile push: the push relay at ${base} has no FCM keys, so Android phones get notifications only while the app is open; set DUSK_FCM_SERVICE_ACCOUNT_FILE on this server (docs/phone-push.md)`
          : `mobile push: the push relay at ${base} has no APNs keys, so iPhones get notifications only while the app is open; set DUSK_APNS_* on this server (docs/phone-push.md)`);
      }
      return "skipped";
    }
    if (!response.ok) return "failed";
    return answer?.outcome === "sent" || answer?.outcome === "gone" ? answer.outcome : "failed";
  }

  /** relay and service pairs the relay answered not_configured for, and when: asked again after RELAY_RECHECK_MS */
  const lacking = new Map<string, number>();
  const told = new Set<PushService>();
  const relayLacks = (base: string, service: PushService) => {
    const at = lacking.get(`${base}\n${service}`);
    return at !== undefined && now() - at < RELAY_RECHECK_MS;
  };
  const relayFor = (service: PushService) => {
    if (configured.includes(service)) return null;
    const base = deps.relay?.() ?? null;
    return base && !relayLacks(base, service) ? base : null;
  };
  let warned = false;
  return {
    configured,
    delivers: (service) => configured.includes(service) || relayFor(service) !== null,
    async send(target, message) {
      const base = configured.includes(target.service) ? null : deps.relay?.() ?? null;
      if (base && relayLacks(base, target.service)) return "skipped";
      const relay = base;
      if (!configured.length && !relay && !warned) {
        warned = true;
        log("mobile push: no APNs or FCM credentials and no push relay on this server; phones get notifications only while the app is open");
      }
      if (!configured.includes(target.service) && !relay) return "skipped";
      try {
        const { title: _title, ...shown } = message;
        if (relay) return await sendRelay(relay, target, { message: shown });
        return await (target.service === "apns" ? sendApns(target, { type: "alert" }, apnsAlertBody(message)) : sendFcm(target, message));
      } catch {
        return "failed";
      }
    },
    async status() {
      const relay = deps.relay?.() ?? null;
      let relayServices: PushService[] | null = null;
      if (relay) {
        try {
          const response = await fetch(`${relay}/v1/push`, { signal: AbortSignal.timeout(5_000) });
          const answer = await response.json().catch(() => null) as { services?: unknown } | null;
          if (response.ok && Array.isArray(answer?.services)) relayServices = answer.services.filter((one): one is PushService => one === "apns" || one === "fcm");
        } catch {}
      }
      return { own: [...configured], relay, relayServices };
    },
    async sendActivity(target, activity) {
      if (target.service !== "apns") return "skipped";
      const relay = relayFor("apns");
      if (!configured.includes("apns") && !relay) return "skipped";
      try {
        if (relay) return await sendRelay(relay, target, { activity });
        return await sendApns(target, { type: "liveactivity", priority: activity.priority }, activityApnsBody(activity));
      } catch {
        return "failed";
      }
    },
  };
}
