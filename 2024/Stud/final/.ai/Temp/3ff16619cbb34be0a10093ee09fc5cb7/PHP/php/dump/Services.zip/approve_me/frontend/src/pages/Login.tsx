import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { FaSnowflake, FaEnvelope, FaLock, FaGift } from 'react-icons/fa';
import Snowfall from '../components/Snowfall';

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await login(formData.email, formData.password);
      navigate('/events');
    } catch (err) {
      setError('Invalid email or password');
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center relative">
      <Snowfall />
      
      <div className="card max-w-md w-full p-8">
        <div className="text-center mb-8">
          <FaGift className="text-5xl text-emerald-600 mx-auto mb-4" />
          <h1 className="festive-header justify-center">Welcome Back!</h1>
          <p className="text-emerald-600 mt-2">Sign in to join the holiday festivities</p>
        </div>

        {error && (
          <div className="bg-red-50 text-red-800 p-3 rounded-md mb-4 text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="relative">
            <label className="block text-sm font-medium text-emerald-800 mb-1">
              Email Address
            </label>
            <div className="relative">
              <input
                type="email"
                className="input pl-10"
                value={formData.email}
                onChange={e => setFormData({ ...formData, email: e.target.value })}
                required
              />
              <FaEnvelope className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500" />
            </div>
          </div>

          <div className="relative">
            <label className="block text-sm font-medium text-emerald-800 mb-1">
              Password
            </label>
            <div className="relative">
              <input
                type="password"
                className="input pl-10"
                value={formData.password}
                onChange={e => setFormData({ ...formData, password: e.target.value })}
                required
              />
              <FaLock className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500" />
            </div>
          </div>

          <button type="submit" className="btn btn-primary w-full">
            Sign In
          </button>
        </form>

        <div className="mt-6 text-center">
          <FaSnowflake className="inline-block text-emerald-200 animate-spin-slow mr-2" />
          <span className="text-gray-600">Don't have an account?</span>{' '}
          <Link to="/register" className="text-emerald-600 hover:text-emerald-700 font-medium">
            Register
          </Link>
        </div>
      </div>
    </div>
  );
} 