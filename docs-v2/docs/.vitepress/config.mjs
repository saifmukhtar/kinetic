import { defineConfig } from 'vitepress'

export default defineConfig({
  title: "Kinetic",
  description: "A gasless, blockchain-free P2P naming network.",
  // Default to light mode as requested by the user, while keeping the toggle
  appearance: true, 
  themeConfig: {
    logo: '/logo.svg', // Assuming we have a logo
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/introduction' }
    ],
    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Introduction', link: '/introduction' },
          { text: 'Architecture', link: '/architecture' },
          { text: 'VDF Consensus', link: '/vdf_consensus' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/saif/kinetic' }
    ]
  }
})
