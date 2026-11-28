// @vitest-environment happy-dom
import { act, createElement, StrictMode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MobileConnectionRecord, MobileOpenTarget } from "../../shared/mobile-link";
import type { Action, AppState } from "@/state/store";
import type { MobilePlatform } from "./platform";
import { usePhoneActions } from "./use-phone-actions";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const connections = [
  { id: "home", environmentId: "env-home" },
  { id: "cloud", environmentId: "env-cloud" },
] as MobileConnectionRecord[];
const state = { hydrated: true, connected: true } as AppState;
let root: Root;
let host: HTMLDivElement;
let fire: (action: { actionId: string; inputValue?: string; data: Record<string, unknown> }) => void;

beforeEach(() => {
  sessionStorage.clear();
  host = document.createElement("div");
  root = createRoot(host);
  fire = () => {};
});
afterEach(() => { act(() => root.unmount()); });

function mount(place: string) {
  const dispatch = vi.fn<(action: Action) => void>();
  const openTarget = vi.fn<(target: MobileOpenTarget) => void>();
  const switchTo = vi.fn(async (_id: string) => {});
  const platform = { onPhoneAction: (listener: typeof fire) => { fire = listener; return () => {}; } } as MobilePlatform;
  function Probe() {
    usePhoneActions(platform, state, dispatch, openTarget, { place, connections, loaded: true, switchTo });
    return null;
  }
  act(() => root.render(createElement(StrictMode, null, createElement(Probe))));
  return { dispatch, openTarget, switchTo };
}

function reload() {
  act(() => root.unmount());
  root = createRoot(host);
}

describe("notification actions from another linked place", () => {
  it("opens the exact cloud conversation only after switching away from Home", () => {
    const home = mount("home");
    act(() => fire({ actionId: "tap", data: { kind: "done", environmentId: "env-cloud", botId: "cloud-bot", threadId: "cloud-side-thread", id: "notification-1" } }));
    expect(home.switchTo).toHaveBeenCalledWith("cloud");
    expect(home.openTarget).not.toHaveBeenCalled();
    expect(home.dispatch).not.toHaveBeenCalled();

    reload();
    const cloud = mount("cloud");
    expect(cloud.openTarget).toHaveBeenCalledWith({ environmentId: "env-cloud", botId: "cloud-bot", threadId: "cloud-side-thread" });
    expect(cloud.dispatch).not.toHaveBeenCalled();
  });

  it("does not send a notification reply to the currently open, wrong place", () => {
    const home = mount("home");
    act(() => fire({ actionId: "dusk.reply", inputValue: "Answer from fixture", data: { kind: "done", environmentId: "env-cloud", botId: "cloud-bot", threadId: "cloud-thread", id: "notification-2" } }));
    expect(home.switchTo).toHaveBeenCalledWith("cloud");
    expect(home.dispatch).not.toHaveBeenCalled();

    reload();
    const cloud = mount("cloud");
    expect(cloud.dispatch).toHaveBeenCalledWith({ type: "send", botId: "cloud-bot", text: "Answer from fixture", threadId: "cloud-thread" });
  });

  it("drops a held action if the requested place did not become active", () => {
    const home = mount("home");
    act(() => fire({ actionId: "dusk.approve", data: { kind: "approval", environmentId: "env-cloud", botId: "cloud-bot", threadId: "cloud-thread", requestId: "ask-1" } }));
    expect(home.switchTo).toHaveBeenCalledWith("cloud");
    expect(home.dispatch).not.toHaveBeenCalled();

    reload();
    const stillHome = mount("home");
    expect(stillHome.switchTo).not.toHaveBeenCalled();
    expect(stillHome.dispatch).not.toHaveBeenCalled();
  });
});
