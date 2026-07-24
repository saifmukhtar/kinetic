<template>
  <div class="vdf-widget">
    <div class="widget-header">
      <span class="widget-title">🎛️ Interactive VDF Time Calculator</span>
      <span class="widget-subtitle">Drag slider to test exact protocol Squatter Cliff scaling</span>
    </div>

    <div class="slider-row">
      <div class="slider-info">
        <label class="slider-label">Domain Length: <strong>{{ charLength }} characters</strong></label>
        <span class="cliff-badge">{{ stats.badge }}</span>
      </div>
      <input 
        type="range" 
        min="2" 
        max="63" 
        v-model.number="charLength" 
        class="vdf-slider" 
      />
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <span class="stat-num">{{ stats.time }}</span>
        <span class="stat-lbl">Compute Wait Time</span>
      </div>
      <div class="stat-card">
        <span class="stat-num">{{ stats.iterations }}</span>
        <span class="stat-lbl">VDF Iterations</span>
      </div>
      <div class="stat-card highlight">
        <span class="stat-num">$0</span>
        <span class="stat-lbl">Registration Fee</span>
      </div>
    </div>

    <div class="widget-footer">
      <span class="footer-note">
        💡 <strong>Squatter Cliff Curve:</strong> Short names (2-4 chars) require up to 5 months of CPU squarings; standard names (21-62 chars) require 30 mins; 63-char names use a probabilistic hash roll!
      </span>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const charLength = ref(8)

const stats = computed(() => {
  const len = charLength.value
  if (len <= 2) {
    return { time: '~5 months', iterations: '1.71 Trillion', badge: '⚠️ Ultra Squatter Cliff' }
  } else if (len === 3) {
    return { time: '~3 months', iterations: '1.03 Trillion', badge: '⚠️ High Friction Cliff' }
  } else if (len === 4) {
    return { time: '~15 days', iterations: '171 Billion', badge: '⏱️ Heavy Time Lock' }
  } else if (len === 5) {
    return { time: '~1 day', iterations: '11.4 Billion', badge: '⏱️ Moderate Time Lock' }
  } else if (len === 6) {
    return { time: '~12 hours', iterations: '5.7 Billion', badge: '⚡ Standard Cliff' }
  } else if (len === 7) {
    return { time: '~2.5 hours', iterations: '1.19 Billion', badge: '⚡ Fast Registration' }
  } else if (len >= 8 && len <= 10) {
    return { time: '~2 hours', iterations: '955 Million', badge: '⚡ Fast Registration' }
  } else if (len >= 11 && len <= 17) {
    return { time: '~1.5 hours', iterations: '716 Million', badge: '⚡ Standard Registration' }
  } else if (len >= 18 && len <= 20) {
    return { time: '~1 hour', iterations: '477 Million', badge: '⚡ Standard Registration' }
  } else if (len >= 21 && len <= 62) {
    return { time: '~30 minutes', iterations: '238.8 Million', badge: '✅ Baseline Delay (Default)' }
  } else if (len === 63) {
    return { time: '63s – 63 days', iterations: 'Hash Roll', badge: '🎰 63-Char Jackpot Roll' }
  } else {
    return { time: '~30 minutes', iterations: '238.8 Million', badge: 'Baseline Delay' }
  }
})
</script>

<style scoped>
.vdf-widget {
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
  margin-bottom: 1.25rem;
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

.slider-row {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1.25rem;
}

.slider-info {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.slider-label {
  font-size: 0.875rem;
  color: var(--ink);
}

.cliff-badge {
  font-family: var(--vp-font-family-mono);
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--amber-dark);
}

.vdf-slider {
  accent-color: var(--amber);
  height: 6px;
  border-radius: 3px;
  cursor: pointer;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.stat-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 0.75rem 0.5rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 6px;
}

.stat-card.highlight {
  border-color: var(--amber);
  background: var(--amber-soft);
}

.stat-num {
  font-family: var(--vp-font-family-mono);
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--amber-dark);
}

.stat-lbl {
  font-size: 0.7rem;
  color: var(--ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-top: 0.2rem;
}

.widget-footer {
  font-size: 0.8rem;
  color: var(--ink-secondary);
  line-height: 1.4;
  border-top: 1px solid var(--border);
  padding-top: 0.75rem;
}

@media (max-width: 600px) {
  .stats-grid {
    grid-template-columns: 1fr;
  }
}
</style>
