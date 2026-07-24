<template>
  <div class="vdf-widget">
    <div class="widget-header">
      <span class="widget-title">🎛️ Interactive VDF Time Calculator</span>
      <span class="widget-subtitle">Evaluates <code>consensus_math.rs</code> required iterations & delay formula</span>
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
        💡 <strong>Rust Source (<code>kinetic-core/src/consensus_math.rs</code>):</strong> 
        Calculates <code>(BENCHMARK_BASE_ITERATIONS * target_minutes) / BENCHMARK_TARGET_MINUTES</code>. 2-char labels require 30 days of CPU squarings (343.9B iterations); 21-62 char labels require 30 mins (238.8M iterations).
      </span>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const charLength = ref(8)
const BASE = 238819830
const TM = 30

const stats = computed(() => {
  const len = charLength.value
  
  if (len === 63) {
    return {
      time: '63s – 63 Millennia',
      iterations: 'Probabilistic Hash Roll',
      badge: '🎰 63-Char Jackpot Roll'
    }
  }

  let minutes = 30
  let badge = 'Baseline Delay (30m)'

  if (len <= 1) {
    minutes = 52596000
    badge = '⛔ 100 Years (Reserved)'
  } else if (len === 2) {
    minutes = 43200
    badge = '⚠️ 30 Days (Ultra Cliff)'
  } else if (len === 3) {
    minutes = 34560
    badge = '⚠️ 24 Days (High Cliff)'
  } else if (len === 4) {
    minutes = 21600
    badge = '⏱️ 15 Days (Time Lock)'
  } else if (len === 5) {
    minutes = 1440
    badge = '⏱️ 1 Day (Time Lock)'
  } else if (len === 6) {
    minutes = 720
    badge = '⚡ 12 Hours (Standard Cliff)'
  } else if (len === 7) {
    minutes = 150
    badge = '⚡ 2.5 Hours (Fast)'
  } else if (len >= 8 && len <= 10) {
    minutes = 120
    badge = '⚡ 2 Hours (Fast)'
  } else if (len >= 11 && len <= 17) {
    minutes = 90
    badge = '⚡ 1.5 Hours (Fast)'
  } else if (len >= 18 && len <= 20) {
    minutes = 60
    badge = '⚡ 1 Hour (Standard)'
  } else if (len >= 21 && len <= 62) {
    minutes = 30
    badge = '✅ 30 Mins (Baseline Target)'
  }

  const iterations = Math.round((BASE * minutes) / TM)
  
  let iterStr = iterations.toLocaleString()
  if (iterations >= 1e12) {
    iterStr = `${(iterations / 1e12).toFixed(2)} Trillion`
  } else if (iterations >= 1e9) {
    iterStr = `${(iterations / 1e9).toFixed(2)} Billion`
  } else if (iterations >= 1e6) {
    iterStr = `${(iterations / 1e6).toFixed(1)} Million`
  }

  let timeStr = `${minutes} mins`
  if (minutes >= 52596000) {
    timeStr = '100 Years'
  } else if (minutes >= 1440) {
    const days = Math.round(minutes / 1440)
    timeStr = `~${days} Day${days > 1 ? 's' : ''}`
  } else if (minutes >= 60) {
    const hours = (minutes / 60).toFixed(1)
    timeStr = `~${hours} Hours`
  }

  return {
    time: timeStr,
    iterations: iterStr,
    badge
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
