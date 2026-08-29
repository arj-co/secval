'use client';

import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import AgentSecurityControlCenter from '../page';

function AppBootScreen() {
  return (
    <main className="app-boot-screen" aria-label="Loading SecVal control center">
      <div className="app-boot-orbit app-boot-orbit-one" />
      <div className="app-boot-orbit app-boot-orbit-two" />
      <div className="app-boot-mark"><ShieldCheck size={28} strokeWidth={1.8} /></div>
      <div className="app-boot-copy">
        <span>SecVal</span>
        <p>Preparing the authorization layer</p>
      </div>
      <div className="app-boot-status">
        <span className="app-boot-dot" />
        <span>Checking local runtime</span>
      </div>
      <div className="app-boot-progress" aria-hidden="true"><span /></div>
    </main>
  );
}

export default function AppEntry() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const timer = window.setTimeout(() => setReady(true), 1450);
    return () => window.clearTimeout(timer);
  }, []);

  return ready ? <AgentSecurityControlCenter /> : <AppBootScreen />;
}
