import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

const originalFetch = window.fetch;
window.fetch = async (input, init) => {
  const token = localStorage.getItem('kinetic_auth_token');
  if (typeof input === 'string' && input.startsWith('/api/')) {
    init = init || {};
    init.headers = {
      ...init.headers,
      ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    };
  }
  const res = await originalFetch(input, init);
  if (res.status === 401 && window.location.pathname !== '/settings') {
    alert('Authentication token is missing or invalid. Please check your settings.');
    window.location.href = '/settings';
  }
  return res;
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
