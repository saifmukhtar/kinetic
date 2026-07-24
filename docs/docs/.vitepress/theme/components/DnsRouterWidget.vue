<template>
  <div class="dns-widget">
    <div class="widget-header">
      <span class="widget-title">🌐 Split-DNS Gateway Visualizer</span>
      <span class="widget-subtitle">Click a request type to see how local routing works</span>
    </div>

    <div class="btn-group">
      <button 
        class="tab-btn" 
        :class="{ active: activeTab === 'kin' }" 
        @click="activeTab = 'kin'"
      >
        Resolving <code>alice.kin</code>
      </button>
      <button 
        class="tab-btn" 
        :class="{ active: activeTab === 'com' }" 
        @click="activeTab = 'com'"
      >
        Resolving <code>github.com</code>
      </button>
    </div>

    <div class="flow-container">
      <div class="flow-step" :class="{ active: true }">
        <span class="step-num">1</span>
        <span class="step-desc">Browser requests <code>{{ activeTab === 'kin' ? 'alice.kin' : 'github.com' }}</code></span>
      </div>

      <div class="flow-arrow">↓</div>

      <div class="flow-step highlight">
        <span class="step-num">2</span>
        <span class="step-desc"><strong>Local `kinetic-daemon` (127.0.0.2:53)</strong> intercepts query</span>
      </div>

      <div class="flow-arrow">↓</div>

      <div v-if="activeTab === 'kin'" class="flow-step success">
        <span class="step-num">3</span>
        <span class="step-desc">Recognizes <code>.kin</code> → Queries <strong>Local Kademlia DHT Swarm</strong> ($0 fees)</span>
      </div>

      <div v-else class="flow-step passthrough">
        <span class="step-num">3</span>
        <span class="step-desc">Recognizes non-<code>.kin</code> → Passes through to <strong>OS System Resolver</strong> (1.1.1.1)</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const activeTab = ref('kin')
</script>

<style scoped>
.dns-widget {
  margin: 2rem 0;
  padding: 1.5rem;
  background: var(--bg-subtle);
  border: 1px solid var(--border-strong);
  border-radius: 8px;
  box-shadow: var(--shadow-offset);
}

.widget-header {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  margin-bottom: 1rem;
}

.widget-title {
  font-family: var(--font-heading);
  font-size: 1.1rem;
  font-weight: 650;
  color: var(--ink);
}

.widget-subtitle {
  font-size: 0.8rem;
  color: var(--ink-muted);
}

.btn-group {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.25rem;
}

.tab-btn {
  padding: 0.4rem 0.85rem;
  font-size: 0.85rem;
  font-family: var(--vp-font-family-base);
  border: 1.5px solid var(--border-strong);
  border-radius: 5px;
  background: var(--bg-elevated);
  cursor: pointer;
  transition: all 150ms ease;
}

.tab-btn.active {
  background: var(--ink);
  color: var(--bg-base);
  border-color: var(--ink);
}

.flow-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.4rem;
}

.flow-step {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  width: 100%;
  padding: 0.65rem 1rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.85rem;
}

.flow-step.highlight {
  border-color: var(--amber);
  background: var(--amber-soft);
}

.flow-step.success {
  border-color: #167A6E;
  background: #D0EDE9;
  color: #167A6E;
}

.flow-step.passthrough {
  border-color: var(--border-strong);
  background: var(--bg-muted);
}

.step-num {
  font-family: var(--vp-font-family-mono);
  font-size: 0.75rem;
  font-weight: 700;
  width: 20px;
  height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: var(--border-strong);
}

.flow-arrow {
  font-size: 0.8rem;
  color: var(--ink-muted);
}
</style>
