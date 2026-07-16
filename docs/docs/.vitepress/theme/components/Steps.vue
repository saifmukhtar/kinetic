<template>
  <div class="steps-container">
    <slot></slot>
  </div>
</template>

<style scoped>
.steps-container {
  margin: 2rem 0;
  padding-left: 0;
  list-style: none;
  counter-reset: step-counter;
}
</style>
