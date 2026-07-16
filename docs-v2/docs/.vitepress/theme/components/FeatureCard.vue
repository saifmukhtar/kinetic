<script setup>
import { defineAsyncComponent } from 'vue'

const props = defineProps({
  title: String,
  icon: String // pass the name of the heroicon, e.g., 'ShieldCheckIcon'
})

// Dynamically import the heroicon (outline version)
const IconComponent = props.icon ? defineAsyncComponent(() =>
  import('@heroicons/vue/24/outline').then(module => module[props.icon])
) : null
</script>

<template>
  <div class="feature-card">
    <div class="icon-wrapper" v-if="IconComponent">
      <component :is="IconComponent" class="icon" />
    </div>
    <h3 class="title">{{ title }}</h3>
    <div class="description">
      <slot></slot>
    </div>
  </div>
</template>

<style scoped>
.feature-card {
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-border);
  border-radius: 12px;
  padding: 1.5rem;
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.feature-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 10px 20px -10px rgba(0,0,0,0.1);
  border-color: var(--vp-c-brand-1);
}

.icon-wrapper {
  background: var(--vp-c-bg);
  width: 48px;
  height: 48px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--vp-c-border);
}

.icon {
  width: 24px;
  height: 24px;
  color: var(--vp-c-brand-1);
}

.title {
  margin: 0 !important;
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.description {
  font-size: 0.95rem;
  color: var(--vp-c-text-2);
  line-height: 1.5;
}
</style>
