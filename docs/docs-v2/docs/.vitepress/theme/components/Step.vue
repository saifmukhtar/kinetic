<script setup>
defineProps({
  title: String
})
</script>

<template>
  <div class="step-item">
    <div class="step-marker"></div>
    <div class="step-content">
      <h3 v-if="title" class="step-title">{{ title }}</h3>
      <slot></slot>
    </div>
  </div>
</template>

<style scoped>
.step-item {
  position: relative;
  padding-left: 3rem;
  margin-bottom: 2rem;
}

.step-item:last-child {
  margin-bottom: 0;
}

.step-item::before {
  content: '';
  position: absolute;
  top: 32px;
  bottom: -2rem; /* Extend to next step */
  left: 15px; /* Center of marker */
  width: 2px;
  background: var(--vp-c-border);
  z-index: 0;
}

.step-item:last-child::before {
  display: none;
}

.step-marker {
  position: absolute;
  top: 0;
  left: 0;
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--vp-c-bg);
  border: 2px solid var(--vp-c-brand-1);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1;
  counter-increment: step-counter;
}

.step-marker::after {
  content: counter(step-counter);
  color: var(--vp-c-brand-1);
  font-weight: 600;
  font-size: 0.9rem;
}

.step-title {
  margin: 0 0 0.5rem 0 !important;
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
  padding-top: 4px; /* Align with marker */
}

.step-content {
  color: var(--vp-c-text-2);
}
</style>
