import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { Globe, Settings, Plus, Activity, Home, ShieldAlert } from 'lucide-react';
import './index.css';

// Pages
import Dashboard from './pages/Dashboard';
import Registration from './pages/Registration';
import DomainView from './pages/DomainView';
import NetworkStatus from './pages/NetworkStatus';
import Watchtowers from './pages/Watchtowers';
import SettingsView from './pages/Settings';

function App() {
  return (
    <Router>
      <div className="app-container">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="sidebar-logo">
            <Globe className="logo-icon" size={28} color="var(--accent-blue)" />
            Kinetic
          </div>
          
          <nav className="nav-links" style={{ marginTop: '2rem' }}>
            <NavLink 
              to="/" 
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
            >
              <Home size={20} />
              Domains
            </NavLink>
            <NavLink 
              to="/register" 
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
            >
              <Plus size={20} />
              Register Name
            </NavLink>
            <NavLink 
              to="/watchtowers" 
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
            >
              <ShieldAlert size={20} />
              Watchtowers
            </NavLink>
            <NavLink 
              to="/network" 
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
            >
              <Activity size={20} />
              Network Status
            </NavLink>
            <NavLink 
              to="/settings" 
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
            >
              <Settings size={20} />
              Settings
            </NavLink>
          </nav>
        </aside>

        {/* Main Content */}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/register" element={<Registration />} />
            <Route path="/domain/:name" element={<DomainView />} />
            <Route path="/network" element={<NetworkStatus />} />
            <Route path="/watchtowers" element={<Watchtowers />} />
            <Route path="/settings" element={<SettingsView />} />
            {/* Fallbacks */}
            <Route path="*" element={
              <div>
                <h1>Coming Soon</h1>
                <p className="subtitle">This page is under construction.</p>
              </div>
            } />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
