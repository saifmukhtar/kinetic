<template>
  <span class="term-wrapper" @mouseenter="show = true" @mouseleave="show = false" @click="show = !show">
    <span class="term-word"><slot /></span>
    <Transition name="fade">
      <span v-if="show" class="term-tooltip">
        <strong class="tooltip-title">{{ termTitle }}</strong>
        <span class="tooltip-body">{{ termDef }}</span>
      </span>
    </Transition>
  </span>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  name: {
    type: String,
    default: ''
  },
  def: {
    type: String,
    default: ''
  }
})

const show = ref(false)

const GLOSSARY = {
  vdf: {
    title: 'Verifiable Delay Function (VDF)',
    def: 'A mathematical puzzle that takes a guaranteed, non-parallelizable amount of CPU time to compute, but can be verified instantly by anyone.'
  },
  dht: {
    title: 'Distributed Hash Table (DHT)',
    def: 'A peer-to-peer database spread across network nodes without any central server or master database.'
  },
  kid: {
    title: 'Kinetic Identity (KID)',
    def: 'A self-sovereign identity anchored to your local private key (did:kin:...), eliminating the need for email/passwords.'
  },
  tld: {
    title: 'Top-Level Domain (TLD)',
    def: 'The suffix at the end of a domain name, like .kin, .com, or .uni.'
  },
  drand: {
    title: 'Drand Randomness Beacon',
    def: 'A public, verifiable randomness beacon that prevents attackers from pre-computing VDF solutions in advance.'
  },
  ed25519: {
    title: 'Ed25519 Signature Scheme',
    def: 'A high-speed, battle-tested public-key cryptographic signature algorithm used to sign name ownership.'
  },
  splitdns: {
    title: 'Split-DNS Gateway',
    def: 'A local DNS proxy that intercepts .kin queries for the P2P network while passing standard sites (.com) to normal system DNS.'
  }
}

const termTitle = computed(() => {
  if (props.name) {
    const key = props.name.toLowerCase()
    if (GLOSSARY[key]) return GLOSSARY[key].title
  }
  return props.name || 'Term Definition'
})

const termDef = computed(() => {
  if (props.def) return props.def
  if (props.name) {
    const key = props.name.toLowerCase()
    if (GLOSSARY[key]) return GLOSSARY[key].def
  }
  return 'No definition available.'
})
</script>

<style scoped>
.term-wrapper {
  position: relative;
  display: inline-block;
  cursor: help;
}

.term-word {
  border-bottom: 1.5px dotted var(--amber);
  color: var(--ink);
  font-weight: 500;
  transition: color 150ms ease, border-color 150ms ease;
}

.term-wrapper:hover .term-word {
  color: var(--amber-dark);
  border-bottom-style: solid;
}

.term-tooltip {
  position: absolute;
  bottom: 125%;
  left: 50%;
  transform: translateX(-50%);
  width: max-content;
  max-width: 260px;
  padding: 0.65rem 0.85rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  box-shadow: var(--shadow-md);
  z-index: 100;
  pointer-events: none;
  font-size: 0.8rem;
  line-height: 1.45;
  color: var(--ink-secondary);
}

.tooltip-title {
  display: block;
  font-size: 0.75rem;
  font-family: var(--vp-font-family-mono);
  color: var(--amber-dark);
  margin-bottom: 0.25rem;
}

.tooltip-body {
  display: block;
}

.fade-enter-active, .fade-leave-active {
  transition: opacity 150ms ease, transform 150ms ease;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
  transform: translate(-50%, 4px);
}
</style>
