import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Register from './pages/Register';
import EventList from './pages/events/EventList';
import CreateEvent from './pages/events/CreateEvent';
import ManageEvent from './pages/events/ManageEvent';
import PrivateRoute from './components/PrivateRoute';
import BulkImport from './pages/events/BulkImport';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Navigate to="/events" replace />} />
            <Route path="login" element={<Login />} />
            <Route path="register" element={<Register />} />
            <Route path="events" element={<PrivateRoute><EventList /></PrivateRoute>} />
            <Route path="events/create" element={<PrivateRoute><CreateEvent /></PrivateRoute>} />
            <Route path="events/manage/:id" element={<PrivateRoute><ManageEvent /></PrivateRoute>} />
            <Route path="events/import" element={<PrivateRoute><BulkImport /></PrivateRoute>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
