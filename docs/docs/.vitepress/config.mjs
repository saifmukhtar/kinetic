import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(defineConfig({
  title: "Kinetic",
  description: "The sovereign namespace engine. Deploy your own cryptographically secured naming network, or use the public .kin network — no fees, no central authorities.",
  ignoreDeadLinks: true,
  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.googleapis.com' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' }],
    ['link', {
      rel: 'stylesheet',
      href: 'https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Outfit:wght@500;600;700&family=Plus+Jakarta+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap'
    }],
    ['meta', { name: 'og:title', content: 'Kinetic — Sovereign Namespace Engine' }],
    ['meta', { name: 'og:description', content: 'Deploy your own cryptographically secured naming network. Or use the public .kin network — no fees, no central authorities, no global ledgers.' }],
    ['meta', { property: 'og:image', content: '/og-image.png' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }]
  ],
  appearance: 'force-auto',
  markdown: {
    math: true,
    theme: {
      light: 'github-light',
      dark: 'github-dark'
    }
  },
  themeConfig: {
    logo: '/favicon.svg',
    siteTitle: 'Kinetic',

    // ── Top navigation ───────────────────────────────────────
    nav: [
      { text: 'Home', link: '/' },
      { text: 'For Users', link: '/users/' },
      { text: 'For Developers', link: '/developers/' },
      {
        text: 'Deep Dive',
        items: [
          { text: 'How Kinetic Works', link: '/architecture/01-philosophy' },
          { text: 'Fork Operators',    link: '/operators/' },
          { text: 'Protocol Spec v1',  link: '/protocol_specification' },
          { text: 'Adversarial Analysis', link: '/adversarial_analysis' },
          {
            text: 'Whitepapers',
            link: 'https://github.com/saifmukhtar/kinetic/tree/main/whitepaper'
          }
        ]
      }
    ],

    // ── Sidebars — each audience gets a curated journey ─────
    sidebar: {

      // ══════════════════════════════════════════════════════
      //  FOR USERS — journey: install → register → keep alive
      // ══════════════════════════════════════════════════════
      '/users/': [
        {
          text: 'Getting Started',
          collapsed: false,
          items: [
            { text: 'Overview',               link: '/users/' },
            { text: 'Desktop App (GUI)',       link: '/users/desktop-app' },
            { text: 'Install on Linux',        link: '/users/install-linux' },
            { text: 'Install on macOS',        link: '/users/install-macos' },
            { text: 'Install on Windows',      link: '/users/install-windows' }
          ]
        },
        {
          text: 'Your Names',
          collapsed: false,
          items: [
            { text: 'Register a Name',         link: '/users/register' },
            { text: 'Manage DNS Records',      link: '/users/dns-records' },
            { text: 'Renew Your Name',         link: '/users/renew' }
          ]
        },
        {
          text: 'Identity & Security',
          collapsed: false,
          items: [
            { text: 'Seed Phrase & Backup',    link: '/users/seed-backup' },
            { text: 'File Paths Reference',    link: '/users/file-paths' }
          ]
        },
        {
          text: 'Troubleshooting',
          collapsed: false,
          items: [
            { text: 'Common Problems & Fixes', link: '/users/troubleshooting' },
            { text: 'Error Code Lookup',       link: '/users/errors' }
          ]
        },
        {
          text: 'Under the Hood',
          collapsed: true,
          items: [
            { text: 'How Kinetic Works →',     link: '/architecture/01-philosophy' },
            { text: 'Identity Architecture (KID)', link: '/kinetic-kid' },
            { text: 'The Split-DNS Gateway',   link: '/dns_loopback' },
            { text: 'Name Lifecycle & Heartbeats', link: '/heartbeat' },
            { text: 'Protocol Specification',  link: '/protocol_specification' }
          ]
        }
      ],

      // ══════════════════════════════════════════════════════
      //  FOR DEVELOPERS — journey: auth → API → SDKs → examples
      // ══════════════════════════════════════════════════════
      '/developers/': [
        {
          text: 'Overview',
          collapsed: false,
          items: [
            { text: 'Introduction',             link: '/developers/' },
            { text: 'Authentication',           link: '/developers/auth' }
          ]
        },
        {
          text: 'REST API',
          collapsed: false,
          items: [
            { text: 'Overview & Base URL',      link: '/developers/api/' },
            { text: 'Public Endpoints',         link: '/developers/api/public' },
            { text: 'Authenticated Endpoints',  link: '/developers/api/authenticated' }
          ]
        },
        {
          text: 'SDKs',
          collapsed: false,
          items: [
            { text: 'TypeScript SDK',           link: '/developers/sdk-typescript' },
            { text: 'Rust SDK',                 link: '/developers/sdk-rust' }
          ]
        },
        {
          text: 'Worked Examples',
          collapsed: false,
          items: [
            { text: 'Resolve a Name',           link: '/developers/examples/resolve' },
            { text: 'Register a Name',          link: '/developers/examples/register' },
            { text: 'Publish DNS Records',      link: '/developers/examples/publish-dns' }
          ]
        },
        {
          text: 'Protocol Reference',
          collapsed: true,
          items: [
            { text: 'Protocol Specification v1', link: '/protocol_specification' },
            { text: 'Identity Architecture (KID)', link: '/kinetic-kid' },
            { text: 'Adversarial Analysis',     link: '/adversarial_analysis' },
            { text: 'Error Handbook',           link: '/error_handbook' },
            { text: 'CLI Reference',            link: '/reference/cli' }
          ]
        }
      ],

      // ══════════════════════════════════════════════════════
      //  FORK OPERATORS — deploy → configure → run
      // ══════════════════════════════════════════════════════
      '/operators/': [
        {
          text: 'Deploy Your Network',
          collapsed: false,
          items: [
            { text: 'Overview',                link: '/operators/' },
            { text: 'Deploy with kinetic-forge', link: '/forking' },
            { text: 'VDF Hardware Calibration', link: '/vdf-calibration' },
            { text: 'Simulation Sandbox',       link: '/kinetic_sim' }
          ]
        },
        {
          text: 'Architecture Internals',
          collapsed: false,
          items: [
            { text: 'Governance Engine',        link: '/architecture/07-governance' },
            { text: 'P2P Routing & DHT',        link: '/network_architecture' },
            { text: 'Cryptography Deep Dive',   link: '/cryptography' },
            { text: 'Storage Engine',           link: '/architecture/05-storage-engine' },
            { text: 'Forks & Compilation',      link: '/architecture/09-forks-and-compilation' }
          ]
        },
        {
          text: 'Security',
          collapsed: false,
          items: [
            { text: 'Threat & Trust Model',     link: '/architecture/10-threat-and-trust-model' },
            { text: 'Adversarial Analysis',     link: '/adversarial_analysis' }
          ]
        },
        {
          text: 'Reference',
          collapsed: true,
          items: [
            { text: 'Protocol Specification',   link: '/protocol_specification' },
            { text: 'Error Handbook',           link: '/error_handbook' },
            { text: 'CLI Reference',            link: '/reference/cli' }
          ]
        }
      ],

      // ══════════════════════════════════════════════════════
      //  HOW KINETIC WORKS — the 10-chapter conceptual series
      // ══════════════════════════════════════════════════════
      '/architecture/': [
        {
          text: 'How Kinetic Works',
          collapsed: false,
          items: [
            { text: '01 — Philosophy',                link: '/architecture/01-philosophy' },
            { text: '02 — Cryptography & Identity',   link: '/architecture/02-cryptography-and-identity' },
            { text: '03 — VDF & Cost',                link: '/architecture/03-vdf-and-cost' },
            { text: '04 — Network Routing',           link: '/architecture/04-network-routing' },
            { text: '05 — Storage Engine',            link: '/architecture/05-storage-engine' },
            { text: '06 — Daemon & DNS',              link: '/architecture/06-daemon-and-dns' },
            { text: '07 — Governance',                link: '/architecture/07-governance' },
            { text: '08 — Client Architecture',       link: '/architecture/08-client-architecture' },
            { text: '09 — Forks & Compilation',       link: '/architecture/09-forks-and-compilation' },
            { text: '10 — Threat & Trust Model',      link: '/architecture/10-threat-and-trust-model' }
          ]
        },
        {
          text: 'Deep Dives',
          collapsed: true,
          items: [
            { text: 'The Mathematical Engine',        link: '/cryptography' },
            { text: 'P2P Routing & Immunological DHT', link: '/network_architecture' },
            { text: 'Name Lifecycle & Heartbeats',    link: '/heartbeat' },
            { text: 'Zero-Dollar Split-DNS Gateway',  link: '/dns_loopback' },
            { text: 'Identity Architecture (KID)',    link: '/kinetic-kid' },
            { text: 'Adversarial Analysis',           link: '/adversarial_analysis' },
            { text: 'Protocol Specification v1',      link: '/protocol_specification' }
          ]
        },
        {
          text: 'Crate Walkthroughs',
          collapsed: true,
          items: [
            { text: 'kinetic-core & kinetic-vdf',     link: '/code_walkthrough_core' },
            { text: 'kinetic-daemon & kinetic-cli',   link: '/code_walkthrough_daemon' },
            { text: 'kinetic-network & kinetic-dns',  link: '/code_walkthrough_network' },
            { text: 'kinetic-client & FFI',           link: '/code_walkthrough_client' },
            { text: 'kinetic-node',                   link: '/kinetic_node' },
            { text: 'kinetic-storage',                link: '/kinetic_storage' }
          ]
        }
      ],

      // ══════════════════════════════════════════════════════
      //  REFERENCE — CLI + error handbook
      // ══════════════════════════════════════════════════════
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'CLI Reference',           link: '/reference/cli' },
            { text: 'Error Handbook',          link: '/error_handbook' },
            { text: 'Protocol Specification',  link: '/protocol_specification' }
          ]
        }
      ],

      // ══════════════════════════════════════════════════════
      //  FALLBACK — deep conceptual pages accessed directly
      // ══════════════════════════════════════════════════════
      '/': [
        {
          text: 'Kinetic',
          items: [
            { text: 'For Users',                link: '/users/' },
            { text: 'For Developers',           link: '/developers/' },
            { text: 'Fork Operators',           link: '/operators/' },
            { text: 'How Kinetic Works',        link: '/architecture/01-philosophy' }
          ]
        },
        {
          text: 'Conceptual Guides',
          items: [
            { text: 'Introduction',             link: '/introduction' },
            { text: 'The Mathematical Engine',  link: '/cryptography' },
            { text: 'P2P Routing & DHT',        link: '/network_architecture' },
            { text: 'Name Lifecycle & Heartbeats', link: '/heartbeat' },
            { text: 'Zero-Dollar Gateway',      link: '/dns_loopback' },
            { text: 'Identity Architecture (KID)', link: '/kinetic-kid' },
            { text: 'Future Horizons',          link: '/future_horizons' },
            { text: 'Adversarial Analysis',     link: '/adversarial_analysis' },
            { text: 'Protocol Specification',   link: '/protocol_specification' }
          ]
        },
        {
          text: 'Legal',
          items: [
            { text: 'Privacy Policy',           link: '/privacy_policy' },
            { text: 'Terms of Service',         link: '/terms_of_service' }
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

    editLink: {
      pattern: 'https://github.com/saifmukhtar/kinetic/edit/main/docs/docs/:path',
      text: 'Edit this page on GitHub'
    },

    lastUpdated: {
      text: 'Updated at',
      formatOptions: {
        dateStyle: 'medium',
        timeStyle: 'short'
      }
    },

    footer: {
      message: 'Released under the CC BY 4.0 License.',
      copyright: 'Copyright © 2026-present Saif Mukhtar | <a href="/privacy_policy">Privacy Policy</a> | <a href="/terms_of_service">Terms of Service</a>'
    }
  }
}))
