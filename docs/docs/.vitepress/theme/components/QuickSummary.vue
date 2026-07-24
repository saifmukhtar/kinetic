<template>
  <div class="quick-summary">
    <div class="summary-header">
      <span class="summary-badge">
        <span class="badge-icon">⚡</span>
        <span class="badge-text">Quick Summary</span>
      </span>
      <span v-if="time" class="summary-time">⏱️ {{ time }} read</span>
    </div>
    <div class="summary-content">
      <slot />
    </div>
  </div>
</template>

<script setup>
defineProps({
  time: {
    type: String,
    default: ''
  }
})
</script>

<style scoped>
.quick-summary {
  margin: 1.5rem 0 2rem;
  padding: 1.25rem 1.5rem;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--border-strong);
  border-left: 4px solid var(--amber);
  border-radius: 6px;
  box-shadow: 3px 4px 0px rgba(26, 23, 20, 0.08);
}

.summary-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
}

.summary-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-family: var(--vp-font-family-mono);
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--amber-dark);
}

.summary-time {
  font-family: var(--vp-font-family-mono);
  font-size: 0.75rem;
  color: var(--ink-muted);
}

.summary-content {
  font-family: var(--vp-font-family-base);
  font-size: 0.9375rem;
  line-height: 1.65;
  color: var(--ink);
}

.summary-content :deep(p) {
  margin: 0;
  color: var(--ink);
}

.dark .quick-summary {
  box-shadow: 3px 4px 0px rgba(0, 0, 0, 0.25);
  border-left-color: var(--amber);
}
</style>
