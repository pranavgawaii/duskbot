import type { MobileOpenTarget } from "../../shared/mobile-link";
import { PHONE_ACTION } from "../../shared/phone-activity";

/** What a notification button, its reply field or a Live Activity button asks the app to do. */
export type PhoneAction =
  | { kind: "decide"; target: MobileOpenTarget; requestId: string; behavior: "allow" | "deny" }
  | { kind: "reply"; target: MobileOpenTarget; text: string }
  | { kind: "open"; target: MobileOpenTarget };

/** A button press as the native layer reports it: the notification's own data (the bot host's `dusk` block, the
 * relay's `omb` block, or a Live Activity's ids at the top level). */
export interface NativeAction {
  actionId: string;
  inputValue?: string;
  data: Record<string, unknown>;
}

const ID = /^[\w:.-]{1,128}$/;
const id = (value: unknown) => (typeof value === "string" && ID.test(value) ? value : undefined);

function idsOf(data: Record<string, unknown>): Record<string, unknown> {
  for (const key of ["dusk", "omb"]) {
    const block = data[key];
    if (block && typeof block === "object") return block as Record<string, unknown>;
  }
  return data;
}

export function phoneActionFrom(action: NativeAction): PhoneAction | null {
  const ids = idsOf(action.data);
  const threadId = id(ids.threadId);
  if (!threadId) return null;
  const botId = id(ids.botId), groupId = id(ids.groupId), requestId = id(ids.requestId), environmentId = id(ids.environmentId);
  const target: MobileOpenTarget = { threadId, ...(botId ? { botId } : {}), ...(groupId ? { groupId } : {}), ...(environmentId ? { environmentId } : {}) };
  if (!botId && !groupId) return null;
  if ((action.actionId === PHONE_ACTION.approve || action.actionId === PHONE_ACTION.deny) && requestId) {
    return { kind: "decide", target, requestId, behavior: action.actionId === PHONE_ACTION.approve ? "allow" : "deny" };
  }
  const text = action.inputValue?.trim();
  if (action.actionId === PHONE_ACTION.reply && text && botId && !groupId) return { kind: "reply", target, text: text.slice(0, 8000) };
  return { kind: "open", target };
}
