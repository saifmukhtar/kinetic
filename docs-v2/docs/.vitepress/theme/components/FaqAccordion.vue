<script setup>
defineProps({
  question: String
})
</script>

<template>
  <details class="faq-accordion">
    <summary>
      <span class="question">{{ question }}</span>
      <svg class="icon" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
      </svg>
    </summary>
    <div class="answer">
      <slot></slot>
    </div>
  </details>
</template>

<style scoped>
.faq-accordion {
  border: 1px solid var(--vp-c-border);
  border-radius: 8px;
  margin-bottom: 1rem;
  background: var(--vp-c-bg-soft);
  overflow: hidden;
}

summary {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 1.25rem;
  cursor: pointer;
  font-weight: 600;
  color: var(--vp-c-text-1);
  user-select: none;
  list-style: none; /* Hide default arrow */
}

summary::-webkit-details-marker {
  display: none;
}

.icon {
  width: 20px;
  height: 20px;
  color: var(--vp-c-text-3);
  transition: transform 0.2s ease;
}

details[open] summary .icon {
  transform: rotate(180deg);
}

details[open] summary {
  border-bottom: 1px solid var(--vp-c-border);
}

.answer {
  padding: 1.25rem;
  color: var(--vp-c-text-2);
  font-size: 0.95rem;
  line-height: 1.6;
}
</style>
