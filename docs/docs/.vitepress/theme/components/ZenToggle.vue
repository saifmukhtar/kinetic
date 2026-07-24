<template>
  <button 
    class="zen-btn" 
    :class="{ active: isZen }" 
    @click="toggleZen" 
    :title="isZen ? 'Exit Zen Reading Mode' : 'Enter Zen Reading Mode'"
  >
    <span class="zen-icon">{{ isZen ? '📖' : '🧘' }}</span>
    <span class="zen-label">{{ isZen ? 'Exit Zen' : 'Zen Read' }}</span>
  </button>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const isZen = ref(false)

function toggleZen() {
  isZen.value = !isZen.value
  if (isZen.value) {
    document.documentElement.classList.add('zen-mode')
  } else {
    document.documentElement.classList.remove('zen-mode')
  }
}

onMounted(() => {
  isZen.value = document.documentElement.classList.contains('zen-mode')
})
</script>

<style scoped>
.zen-btn {
  position: fixed;
  bottom: 1.5rem;
  right: 1.5rem;
  z-index: 100;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 0.85rem;
  font-family: var(--vp-font-family-mono);
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--ink);
  background: var(--bg-elevated);
  border: 1.5px solid var(--border-strong);
  border-radius: 9999px;
  cursor: pointer;
  box-shadow: var(--shadow-offset);
  transition: transform 200ms cubic-bezier(0.34, 1.56, 0.64, 1),
              box-shadow 200ms cubic-bezier(0.34, 1.56, 0.64, 1),
              border-color 150ms ease;
}

.zen-btn:hover {
  transform: translate(-1px, -1px);
  box-shadow: 4px 5px 0px rgba(26, 23, 20, 0.16);
  border-color: var(--amber);
}

.zen-btn.active {
  background: var(--amber-soft);
  border-color: var(--amber);
  color: var(--amber-dark);
}

.zen-icon {
  font-size: 0.9rem;
}

@media (max-width: 768px) {
  .zen-btn {
    bottom: 1rem;
    right: 1rem;
  }
}
</style>
