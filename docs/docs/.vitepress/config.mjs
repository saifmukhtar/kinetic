import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(defineConfig({
  title: "Kinetic",
  description: "The sovereign namespace engine. Deploy your own cryptographically secured naming network, or use the public .kin network — no fees, no central authorities.",
  ignoreDeadLinks: true,
  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
    ['meta', { name: 'og:title', content: 'Kinetic — Sovereign Namespace Engine' }],
    ['meta', { name: 'og:description', content: 'Deploy your own cryptographically secured naming network. Or use the public .kin network — no fees, no central authorities, no global ledgers.' }]
  ],
  appearance: true,
  markdown: {
    math: true
  },
  themeConfig: {
    logo: '/favicon.svg',

    // Top navigation — audience-first
    nav: [
      { text: 'Home', link: '/' },
      { text: 'For Users', link: '/users/' },
      { text: 'For Developers', link: '/developers/' },
      {
        text: 'More',
        items: [
          { text: 'Fork Operators', link: '/forking' },
          { text: 'Cryptography', link: '/cryptography' },
          { text: 'Network Architecture', link: '/network_architecture' },
          { text: 'Whitepapers', link: 'https://github.com/saifmukhtar/kinetic/tree/main/whitepaper' }
        ]
      }
    ],

    // Per-path sidebars — each audience sees only their section
    sidebar: {

      // ── End User Section ──────────────────────────────────────────────
      '/users/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'What is Kinetic?', link: '/users/' },
            { text: 'Install on Linux', link: '/users/install-linux' },
            { text: 'Install on macOS', link: '/users/install-macos' },
            { text: 'Install on Windows', link: '/users/install-windows' }
          ]
        },
        {
          text: 'Your Names',
          items: [
            { text: 'Register a Name', link: '/users/register' },
            { text: 'Manage DNS Records', link: '/users/dns-records' },
            { text: 'Renew Your Name', link: '/users/renew' }
          ]
        },
        {
          text: 'Identity & Security',
          items: [
            { text: 'Seed Phrase & Backup', link: '/users/seed-backup' },
            { text: 'File Paths Reference', link: '/users/file-paths' }
          ]
        },
        {
          text: 'Troubleshooting',
          items: [
            { text: 'Common Problems & Fixes', link: '/users/troubleshooting' },
            { text: 'Error Code Lookup', link: '/users/errors' }
          ]
        }
      ],

      // ── Developer Section ─────────────────────────────────────────────
      '/developers/': [
        {
          text: 'Overview',
          items: [
            { text: 'Introduction', link: '/developers/' },
            { text: 'Authentication', link: '/developers/auth' }
          ]
        },
        {
          text: 'REST API Reference',
          items: [
            { text: 'Overview & Base URL', link: '/developers/api/' },
            { text: 'Public Endpoints', link: '/developers/api/public' },
            { text: 'Authenticated Endpoints', link: '/developers/api/authenticated' }
          ]
        },
        {
          text: 'SDKs',
          items: [
            { text: 'TypeScript SDK', link: '/developers/sdk-typescript' },
            { text: 'Rust SDK', link: '/developers/sdk-rust' }
          ]
        },
        {
          text: 'Worked Examples',
          items: [
            { text: 'Resolve a Name', link: '/developers/examples/resolve' },
            { text: 'Register a Name', link: '/developers/examples/register' },
            { text: 'Publish DNS Records', link: '/developers/examples/publish-dns' }
          ]
        },
        {
          text: 'Reference',
          items: [
            { text: 'Error Codes', link: '/users/errors' }
          ]
        }
      ],

      // ── Fork Operator Section (legacy, kept for now) ──────────────────
      '/forking': [
        {
          text: 'Fork Your Own Network',
          items: [
            { text: 'Deploy with kinetic-forge', link: '/forking' },
            { text: 'VDF Hardware Calibration', link: '/vdf-calibration' },
            { text: 'P2P Routing & DHT', link: '/network_architecture' },
            { text: 'Cryptography Deep Dive', link: '/cryptography' },
            { text: 'Adversarial Analysis', link: '/adversarial_analysis' }
          ]
        }
      ],

      // ── Reference Section ─────────────────────────────────────────────
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'CLI Reference', link: '/reference/cli' },
            { text: 'Error Handbook', link: '/users/errors' },
            { text: 'Protocol Specification', link: '/protocol_specification' }
          ]
        }
      ],

      // ── Fallback — old pages still accessible ─────────────────────────
      '/': [
        {
          text: 'Kinetic',
          items: [
            { text: 'For Users', link: '/users/' },
            { text: 'For Developers', link: '/developers/' },
            { text: 'Fork Operators', link: '/forking' },
            { text: 'Whitepapers', link: 'https://github.com/saifmukhtar/kinetic/tree/main/whitepaper' }
          ]
        },
        {
          text: 'Deep Reference',
          items: [
            { text: 'Cryptography', link: '/cryptography' },
            { text: 'Network Architecture', link: '/network_architecture' },
            { text: 'Protocol Specification', link: '/protocol_specification' },
            { text: 'Adversarial Analysis', link: '/adversarial_analysis' },
            { text: 'Identity (KID)', link: '/kinetic-kid' }
          ]
        },
        {
          text: 'Legal',
          items: [
            { text: 'Privacy Policy', link: '/privacy_policy' },
            { text: 'Terms of Service', link: '/terms_of_service' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/saifmukhtar/kinetic' }
    ],

    search: {
      provider: 'local'
    },

    footer: {
      message: 'Released under the Apache 2.0 License.',
      copyright: 'Copyright © 2026-present Saif Mukhtar | <a href="/privacy_policy">Privacy Policy</a> | <a href="/terms_of_service">Terms of Service</a>'
    }
  }
}))
