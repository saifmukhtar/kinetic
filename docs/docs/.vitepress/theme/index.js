import DefaultTheme from 'vitepress/theme'
import { h } from 'vue'
import './custom.css'

// Import components
import CardGrid from './components/CardGrid.vue'
import FeatureCard from './components/FeatureCard.vue'
import TerminalWindow from './components/TerminalWindow.vue'
import FaqAccordion from './components/FaqAccordion.vue'
import Steps from './components/Steps.vue'
import Step from './components/Step.vue'

// Modern minimal reading components
import QuickSummary from './components/QuickSummary.vue'
import ZenToggle from './components/ZenToggle.vue'
import Term from './components/Term.vue'
import VdfCalculator from './components/VdfCalculator.vue'
import DnsRouterWidget from './components/DnsRouterWidget.vue'
import DeepDive from './components/DeepDive.vue'

export default {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'layout-bottom': () => h(ZenToggle)
    })
  },
  enhanceApp({ app }) {
    // Register components globally
    app.component('CardGrid', CardGrid)
    app.component('FeatureCard', FeatureCard)
    app.component('TerminalWindow', TerminalWindow)
    app.component('FaqAccordion', FaqAccordion)
    app.component('Steps', Steps)
    app.component('Step', Step)

    // Global reading components
    app.component('QuickSummary', QuickSummary)
    app.component('ZenToggle', ZenToggle)
    app.component('Term', Term)
    app.component('VdfCalculator', VdfCalculator)
    app.component('DnsRouterWidget', DnsRouterWidget)
    app.component('DeepDive', DeepDive)
  }
}
