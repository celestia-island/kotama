<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import HButton from "@celestia-island/hikari/components/HkButton";

type Capability = "ReadOnly" | "ReadWrite";
type Rect = { x: number; y: number; width: number; height: number };
type Row = { id: string; label: string; enabled: boolean; rect: Rect };
type Snapshot = {
  expanded: boolean;
  hovered: boolean;
  capability: Capability;
  window_rect: Rect;
  rows: Row[];
};
type Outcome =
  | "Allowed"
  | "Unknown"
  | "Disabled"
  | { Denied: { required: Capability; granted: Capability } };
type Invoked = { id: string | null; outcome: Outcome };

const snapshot = ref<Snapshot | null>(null);
const message = ref("hover to expand");
const setupError = ref("");

async function refresh() {
  try {
    snapshot.value = await invoke<Snapshot>("snapshot_view");
  } catch (error) {
    setupError.value = String(error);
  }
}

async function pointerMoved(event: MouseEvent) {
  try {
    snapshot.value = await invoke<Snapshot>("pointer_moved", {
      x: Math.round(event.clientX),
      y: Math.round(event.clientY),
    });
  } catch (error) {
    setupError.value = String(error);
  }
}

async function pointerLeft() {
  snapshot.value = await invoke<Snapshot>("pointer_left");
}

function describe(outcome: Outcome): string {
  if (typeof outcome === "string") return outcome;
  return "Denied (" + outcome.Denied.granted + " < " + outcome.Denied.required + ")";
}

async function rowClick(row: Row) {
  const current = snapshot.value;
  if (!current) return;
  const invoked = await invoke<Invoked>("click", {
    x: row.rect.x - current.window_rect.x + 2,
    y: row.rect.y - current.window_rect.y + 2,
  });
  message.value = invoked.id
    ? invoked.id + ": " + describe(invoked.outcome)
    : "no action";
}

async function grantWrite() {
  try {
    snapshot.value = await invoke<Snapshot>("grant_write");
    message.value = "write capability granted";
  } catch (error) {
    setupError.value = String(error);
  }
}

async function keydown(event: KeyboardEvent) {
  if (event.key === "Escape") {
    await getCurrentWindow().close();
    return;
  }
  if (event.ctrlKey && event.altKey && event.key === "F12") {
    const invoked = await invoke<Invoked>("press_shortcut", {
      ctrl: true,
      alt: true,
      shift: false,
      meta: false,
      key: "F12",
    });
    message.value = invoked.id
      ? invoked.id + ": " + describe(invoked.outcome)
      : "shortcut unbound";
  }
}

onMounted(async () => {
  await refresh();
  window.addEventListener("mousemove", pointerMoved);
  document.documentElement.addEventListener("mouseleave", pointerLeft);
  window.addEventListener("keydown", keydown);
});

onUnmounted(() => {
  window.removeEventListener("mousemove", pointerMoved);
  document.documentElement.removeEventListener("mouseleave", pointerLeft);
  window.removeEventListener("keydown", keydown);
});
</script>

<template>
  <main class="toolbar" @mouseleave="pointerLeft">
    <header class="title">
      <span class="brand">kotama overlay</span>
      <span class="capability">{{ snapshot?.capability ?? "ReadOnly" }}</span>
      <span class="message" :title="message">{{ message }}</span>
      <HButton
        class="grant"
        size="xs"
        variant="ghost"
        label="write"
        @click.stop="grantWrite"
      />
    </header>
    <p v-if="setupError" class="error">{{ setupError }}</p>
    <div v-if="snapshot?.expanded" class="rows">
      <HButton
        v-for="row in snapshot.rows"
        :key="row.id"
        class="row"
        size="sm"
        variant="secondary"
        :label="row.label"
        :disabled="!row.enabled"
        :style="{
          left: (row.rect.x - snapshot.window_rect.x) + 'px',
          top: (row.rect.y - snapshot.window_rect.y) + 'px',
          width: row.rect.width + 'px',
          height: row.rect.height + 'px',
        }"
        @click="rowClick(row)"
      />
    </div>
  </main>
</template>
