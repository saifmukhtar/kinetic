import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(defineConfig({
  title: "Kinetic",
  description: "A gasless, blockchain-free P2P naming network.",
  ignoreDeadLinks: true,
  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }]
  ],
  // Default to light mode as requested by the user, while keeping the toggle
  appearance: true, 
  markdown: {
    math: true
  },
  themeConfig: {
    logo: '/favicon.svg',
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/introduction' }
    ],
    sidebar: [
      {
        text: 'Track 1: Fork Your Own Network',
        items: [
          { text: 'What is Kinetic?', link: '/introduction' },
          { text: 'Deploy Your Own Network', link: '/forking' },
          { text: 'The Mathematical Engine', link: '/cryptography' },
          { text: 'VDF Hardware Calibration', link: '/vdf-calibration' },
          { text: 'P2P Routing & DHT', link: '/network_architecture' },
          { text: 'Heartbeats & Stealing', link: '/heartbeat' },
          { text: 'Kinetic Simulation Sandbox', link: '/kinetic_sim' }
        ]
      },
      {
        text: 'Track 2: Using the .kin Network',
        items: [
          { text: 'Getting Started', link: '/getting_started' },
          { text: 'The Zero-Dollar Gateway', link: '/dns_loopback' },
          { text: 'Identity Architecture (KID)', link: '/kinetic-kid' },
          { text: 'Future Horizons', link: '/future_horizons' }
        ]
      },
      {
        text: 'Reference',
        items: [
          { text: 'Adversarial Analysis', link: '/adversarial_analysis' },
          { text: 'Protocol Specification', link: '/protocol_specification' },
          { text: 'Error Handbook', link: '/error_handbook' }
        ]
      },
      {
        text: 'Crate Documentation',
        items: [
          { text: 'kinetic-core & vdf', link: '/code_walkthrough_core' },
          { text: 'kinetic-daemon & cli', link: '/code_walkthrough_daemon' },
          { text: 'kinetic-network & dns', link: '/code_walkthrough_network' },
          { text: 'kinetic-client & FFI', link: '/code_walkthrough_client' },
          { text: 'kinetic-node', link: '/kinetic_node' },
          { text: 'kinetic-storage', link: '/kinetic_storage' }
        ]
      },
      {
        text: 'Legal',
        items: [
          { text: 'Privacy Policy', link: '/privacy_policy' },
          { text: 'Terms of Service', link: '/terms_of_service' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/saifmukhtar/kinetic' }
    ],
    footer: {
      message: 'Released under the CC BY 4.0 License.',
      copyright: 'Copyright © 2026-present Saif Mukhtar | <a href="/privacy_policy">Privacy Policy</a> | <a href="/terms_of_service">Terms of Service</a>'
    }
  }
}))
