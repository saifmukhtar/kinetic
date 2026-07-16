import DefaultTheme from 'vitepress/theme'
import './custom.css'

// Import components
import CardGrid from './components/CardGrid.vue'
import FeatureCard from './components/FeatureCard.vue'
import TerminalWindow from './components/TerminalWindow.vue'
import FaqAccordion from './components/FaqAccordion.vue'
import Steps from './components/Steps.vue'
import Step from './components/Step.vue'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    // Register components globally
    app.component('CardGrid', CardGrid)
    app.component('FeatureCard', FeatureCard)
    app.component('TerminalWindow', TerminalWindow)
    app.component('FaqAccordion', FaqAccordion)
    app.component('Steps', Steps)
    app.component('Step', Step)
  }
}
