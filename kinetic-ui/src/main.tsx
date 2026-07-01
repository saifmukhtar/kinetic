import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

const originalFetch = window.fetch;
window.fetch = async (input, init) => {
  const token = localStorage.getItem('kinetic_auth_token');
  if (token && typeof input === 'string' && input.startsWith('/api/')) {
    init = init || {};
    init.headers = {
      ...init.headers,
      'Authorization': `Bearer ${token}`
    };
  }
  return originalFetch(input, init);
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
