<template>
  <details class="deep-dive-card">
    <summary class="deep-dive-summary">
      <span class="summary-title font-heading">
        <span class="icon">🔍</span> {{ title }}
      </span>
      <span class="summary-badge">Technical Deep Dive</span>
    </summary>
    <div class="deep-dive-body">
      <slot />
    </div>
  </details>
</template>

<script setup>
defineProps({
  title: {
    type: String,
    default: 'Technical Deep Dive'
  }
})
</script>

<style scoped>
.deep-dive-card {
  margin: 1.5rem 0;
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  background: var(--bg-subtle);
  overflow: hidden;
  box-shadow: var(--shadow-xs);
  transition: border-color 150ms ease;
}

.deep-dive-card[open] {
  border-color: var(--amber);
}

.deep-dive-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.85rem 1.125rem;
  font-weight: 600;
  cursor: pointer;
  user-select: none;
  background: var(--bg-elevated);
}

.deep-dive-summary:hover {
  background: var(--bg-muted);
}

.summary-title {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-family: var(--font-heading);
  font-size: 0.9375rem;
  color: var(--ink);
}

.summary-badge {
  font-family: var(--vp-font-family-mono);
  font-size: 0.6875rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ink-muted);
}

.deep-dive-body {
  padding: 1.25rem;
  border-top: 1px solid var(--border);
  background: var(--bg-subtle);
}

.deep-dive-body :deep(p:first-child) {
  margin-top: 0;
}
.deep-dive-body :deep(p:last-child) {
  margin-bottom: 0;
}
</style>
