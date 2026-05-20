import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import ErrorBoundary from './components/ErrorBoundary';

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <div className="min-h-screen bg-dark-900">
          <Routes>
            <Route path="/*" element={<Dashboard />} />
          </Routes>
        </div>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
