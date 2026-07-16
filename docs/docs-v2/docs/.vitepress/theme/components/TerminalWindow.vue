<script setup>
defineProps({
  title: {
    type: String,
    default: 'bash'
  }
})
</script>

<template>
  <div class="terminal-window">
    <div class="terminal-header">
      <div class="terminal-buttons">
        <span class="btn close"></span>
        <span class="btn minimize"></span>
        <span class="btn maximize"></span>
      </div>
      <div class="terminal-title">{{ title }}</div>
    </div>
    <div class="terminal-body">
      <slot></slot>
    </div>
  </div>
</template>

<style scoped>
.terminal-window {
  border-radius: 8px;
  background: #1e1e1e; /* Hardcoded dark for terminal feel even in light mode */
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
  margin: 1.5rem 0;
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, 0.1);
}

.terminal-header {
  display: flex;
  align-items: center;
  padding: 0.75rem 1rem;
  background: #2d2d2d;
  border-bottom: 1px solid #1e1e1e;
  position: relative;
}

.terminal-buttons {
  display: flex;
  gap: 8px;
}

.btn {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.close { background: #ff5f56; }
.minimize { background: #ffbd2e; }
.maximize { background: #27c93f; }

.terminal-title {
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
  color: #999;
  font-family: var(--vp-font-family-base);
  font-size: 0.85rem;
  font-weight: 500;
}

.terminal-body {
  padding: 1.25rem;
  color: #e5e5e5;
  font-family: var(--vp-font-family-mono);
  font-size: 0.9rem;
  overflow-x: auto;
}

/* Ensure code blocks inside terminal don't have double backgrounds */
.terminal-body :deep(pre) {
  margin: 0;
  padding: 0;
  background: transparent !important;
}
</style>
