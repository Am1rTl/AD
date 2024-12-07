import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { FaSnowflake, FaEnvelope, FaLock, FaUser, FaTree } from 'react-icons/fa';
import Snowfall from '../components/Snowfall';

export default function Register() {
  const navigate = useNavigate();
  const { register } = useAuth();
  const [formData, setFormData] = useState({ name: '', email: '', password: '' });
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await register(formData.name, formData.email, formData.password);
      navigate('/events');
    } catch (err) {
      setError('Registration failed. Please try again.');
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center relative">
      <Snowfall />
      
      <div className="card max-w-md w-full p-8">
        <div className="text-center mb-8">
          <FaTree className="text-5xl text-emerald-600 mx-auto mb-4" />
          <h1 className="festive-header justify-center">Join the Celebration!</h1>
          <p className="text-emerald-600 mt-2">Create your account to start planning holiday events</p>
        </div>

        {error && (
          <div className="bg-red-50 text-red-800 p-3 rounded-md mb-4 text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="relative">
            <label className="block text-sm font-medium text-emerald-800 mb-1">
              Full Name
            </label>
            <div className="relative">
              <input
                type="text"
                className="input pl-10"
                value={formData.name}
                onChange={e => setFormData({ ...formData, name: e.target.value })}
                required
              />
              <FaUser className="absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500" />
            </div>
          </div>

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

          <button type="submit" className="btn btn-primary w-full group">
            <span className="group-hover:scale-105 transition-transform inline-flex items-center gap-2">
              <FaSnowflake className="text-white" />
              Create Account
            </span>
          </button>
        </form>

        <div className="mt-6 text-center">
          <FaSnowflake className="inline-block text-emerald-200 animate-spin-slow mr-2" />
          <span className="text-gray-600">Already have an account?</span>{' '}
          <Link to="/login" className="text-emerald-600 hover:text-emerald-700 font-medium">
            Sign In
          </Link>
        </div>
      </div>
    </div>
  );
} 