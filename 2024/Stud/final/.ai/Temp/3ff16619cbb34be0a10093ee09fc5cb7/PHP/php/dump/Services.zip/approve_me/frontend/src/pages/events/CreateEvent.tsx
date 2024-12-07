import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import client from '../../api/client';

import { FaGift, FaSnowflake, FaCalendarAlt, FaFileAlt } from 'react-icons/fa';
import Snowfall from '../../components/Snowfall';

export default function CreateEvent() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    privateDetails: '',
    date: ''
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await client.post('/events', formData);
      navigate('/events');
    } catch (error) {
      console.error('Error creating event:', error);
    }
  };

  return (
    <div className="max-w-2xl mx-auto relative">
      <Snowfall />
      <div className="mb-8 flex items-center gap-3">
        <FaGift className="text-3xl text-emerald-600" />
        <h1 className="festive-header">Create Holiday Event</h1>
      </div>
      
      <form onSubmit={handleSubmit} className="card space-y-6">
        <div className="relative">
          <label className="block text-sm font-medium text-emerald-800 mb-1 flex items-center gap-2">
            <FaGift className="text-emerald-600" />
            Event Title
          </label>
          <input
            type="text"
            className="input pl-10"
            value={formData.title}
            onChange={e => setFormData({ ...formData, title: e.target.value })}
            required
            placeholder="e.g., Christmas Party 2024"
          />
          <FaSnowflake className="absolute left-3 top-9 text-emerald-400" />
        </div>
        
        <div className="relative">
          <label className="block text-sm font-medium text-emerald-800 mb-1 flex items-center gap-2">
            <FaFileAlt className="text-emerald-600" />
            Description
          </label>
          <textarea
            className="input pl-10 min-h-[100px]"
            value={formData.description}
            onChange={e => setFormData({ ...formData, description: e.target.value })}
            required
            placeholder="Share the festive details of your event..."
          />
          <FaSnowflake className="absolute left-3 top-9 text-emerald-400" />
        </div>

        <div className="relative">
          <label className="block text-sm font-medium text-emerald-800 mb-1 flex items-center gap-2">
            <FaFileAlt className="text-emerald-600" />
            Private Details
          </label>
          <textarea
            className="input pl-10"
            value={formData.privateDetails}
            onChange={e => setFormData({ ...formData, privateDetails: e.target.value })}
            placeholder="Details only visible to approved participants..."
          />
          <FaSnowflake className="absolute left-3 top-9 text-emerald-400" />
        </div>
        
        <div className="relative">
          <label className="block text-sm font-medium text-emerald-800 mb-1 flex items-center gap-2">
            <FaCalendarAlt className="text-emerald-600" />
            Date & Time
          </label>
          <input
            type="datetime-local"
            className="input pl-10"
            value={formData.date}
            onChange={e => setFormData({ ...formData, date: e.target.value })}
            required
          />
          <FaSnowflake className="absolute left-3 top-9 text-emerald-400" />
        </div>
        
        <button type="submit" className="btn btn-primary w-full flex items-center justify-center gap-2">
          <FaGift className="text-lg" />
          Create Holiday Event
        </button>
      </form>
    </div>
  );
} 