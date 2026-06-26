import { useState } from 'react';
import { WSProvider } from './hooks/useWS';
import Layout from './components/Layout';
import ScanButton from './components/ScanButton';
import Overview from './pages/Overview';
import Devices from './pages/Devices';
import Scans from './pages/Scans';
import Vulnerabilities from './pages/Vulnerabilities';
import Capture from './pages/Capture';

const pages = {
  '/': Overview,
  '/devices': Devices,
  '/scans': Scans,
  '/vulnerabilities': Vulnerabilities,
  '/capture': Capture,
};

export default function App() {
  const [currentPath, setCurrentPath] = useState('/');

  const Page = pages[currentPath] || Overview;

  return (
    <WSProvider>
      <Layout currentPath={currentPath} onNavigate={setCurrentPath}>
        <Page />
      </Layout>
      <ScanButton />
    </WSProvider>
  );
}
