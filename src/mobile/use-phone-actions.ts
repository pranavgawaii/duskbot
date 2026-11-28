import { useCallback, useEffect, useRef } from "react";

import type { Action, AppState } from "@/state/store";
import type { MobileConnectionRecord, MobileOpenTarget } from "../../shared/mobile-link";
import { PHONE_ACTION } from "../../shared/phone-activity";
import { phoneActionFrom, type PhoneAction } from "./phone-actions";
import type { MobilePlatform } from "./platform";

const HELD_KEY = "dusk.mobile.phoneAction.held";

function hold(action: PhoneAction): string | null {
  try {
    const value = JSON.stringify(action);
    sessionStorage.setItem(HELD_KEY, value);
    return value;
  } catch { return null; }
}

function discard(value: string): void {
  try { if (sessionStorage.getItem(HELD_KEY) === value) sessionStorage.removeItem(HELD_KEY); } catch {}
}

function takeHeld(): PhoneAction | null {
  try {
    const saved = sessionStorage.getItem(HELD_KEY);
    sessionStorage.removeItem(HELD_KEY);
    if (!saved) return null;
    const value = JSON.parse(saved) as Partial<PhoneAction>;
    if (!value || typeof value !== "object" || !value.target || typeof value.target !== "object") return null;
    const actionId = value.kind === "decide"
      ? value.behavior === "allow" ? PHONE_ACTION.approve : value.behavior === "deny" ? PHONE_ACTION.deny : ""
      : value.kind === "reply" ? PHONE_ACTION.reply : "tap";
    const action = phoneActionFrom({ actionId, data: { ...value.target, ...(value.kind === "decide" ? { requestId: value.requestId } : {}) },
      ...(value.kind === "reply" && typeof value.text === "string" ? { inputValue: value.text } : {}) });
    return action?.kind === value.kind ? action : null;
  } catch { return null; }
}

/** Approve, Deny, Reply and Answer from a notification or a Live Activity: the app opens on the exact chat and does what
 * was pressed once the workspace is connected. */
export function usePhoneActions(platform: MobilePlatform, state: AppState, dispatch: (action: Action) => void, openTarget: (target: MobileOpenTarget) => void, routing: {
  place: string | null;
  connections: readonly Pick<MobileConnectionRecord, "id" | "environmentId">[];
  loaded: boolean;
  switchTo: (id: string) => Promise<void>;
}) {
  const { place, connections, loaded, switchTo } = routing;
  const queue = useRef<Array<{ action: PhoneAction; resumed: boolean }>>([]);
  const ready = state.hydrated && state.connected && loaded;
  const readyRef = useRef(ready);
  readyRef.current = ready;

  const run = useCallback((action: PhoneAction, resumed = false) => {
    const source = action.target.environmentId;
    const current = connections.find((one) => one.id === place)?.environmentId;
    if (source && source !== current) {
      if (resumed) return;
      const other = connections.find((one) => one.environmentId === source);
      if (!other) return;
      const saved = hold(action);
      if (saved) void switchTo(other.id).catch(() => discard(saved));
      return;
    }
    openTarget(action.target);
    const threadId = action.target.threadId!;
    if (action.kind === "decide") dispatch({ type: "decideRequest", threadId, requestId: action.requestId, behavior: action.behavior });
    else if (action.kind === "reply" && action.target.botId) dispatch({ type: "send", botId: action.target.botId, text: action.text, threadId });
  }, [connections, dispatch, openTarget, place, switchTo]);
  const runRef = useRef(run);
  runRef.current = run;

  useEffect(() => {
    const held = takeHeld();
    if (!held) return;
    if (readyRef.current) runRef.current(held, true);
    else queue.current.unshift({ action: held, resumed: true });
  }, []);

  useEffect(() => platform.onPhoneAction?.((raw) => {
    const action = phoneActionFrom(raw);
    if (!action) return;
    if (readyRef.current) run(action);
    else queue.current.push({ action, resumed: false });
  }), [platform, run]);

  useEffect(() => {
    if (!ready) return;
    for (const { action, resumed } of queue.current.splice(0)) run(action, resumed);
  }, [ready, run]);
}
