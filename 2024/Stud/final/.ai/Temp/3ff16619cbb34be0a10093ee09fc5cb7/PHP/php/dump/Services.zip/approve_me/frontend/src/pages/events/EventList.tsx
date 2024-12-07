import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import client from '../../api/client';
import { useAuth } from '../../contexts/AuthContext';
import LoadingSpinner from '../../components/LoadingSpinner';
import { FaSnowflake, FaFileImport, FaPlus } from 'react-icons/fa';
import Snowfall from '../../components/Snowfall';

interface Event {
  id: number;
  title: string;
  description: string;
  privateDetails?: string;
  date: string;
  creatorId: number;
  status: 'not_applied' | 'pending' | 'approved' | 'declined' | 'creator';
}

export default function EventList() {
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);
  const { user } = useAuth();

  useEffect(() => {
    loadEvents();
  }, []);

  const loadEvents = async () => {
    try {
      const response = await client.get('/events');
      const eventsData = response.data;
      
      const eventsWithStatus = await Promise.all(
        eventsData.map(async (event: Event) => {
          if (event.creatorId === user?.id) {
            return { ...event, status: 'creator' };
          }
          const statusResponse = await client.get(`/events/${event.id}/status`);
          return { ...event, status: statusResponse.data.status };
        })
      );
      
      setEvents(eventsWithStatus);
    } catch (error) {
      console.error('Error loading events:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleApply = async (eventId: number) => {
    await client.post(`/events/${eventId}/apply`);
    setEvents(events.map(event => 
      event.id === eventId 
        ? { ...event, status: 'pending' }
        : event
    ));
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'not_applied':
        return 'bg-gray-200 text-gray-500';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      case 'approved':
        return 'bg-green-100 text-green-800';
      case 'declined':
        return 'bg-red-100 text-red-800';
      case 'creator':
        return 'bg-blue-100 text-blue-800';
      default:
        return '';
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-6 relative">
      <Snowfall />
      <div className="flex justify-between items-center mb-6">
        <h1 className="festive-header">Holiday Events</h1>
        <div className="flex gap-2">
          <Link to="/events/import" className="btn btn-secondary flex items-center gap-2">
            <FaFileImport />
            Import Events
          </Link>
          <Link to="/events/create" className="btn btn-primary flex items-center gap-2">
            <FaPlus />
            Create Event
          </Link>
        </div>
      </div>
      
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {events.map(event => (
          <div key={event.id} className="card group">
            <div className="absolute top-2 right-2">
              <FaSnowflake className="text-emerald-200 text-xl group-hover:animate-spin-slow" />
            </div>
            <div className="flex justify-between items-start">
              <h3 className="text-lg font-semibold">{event.title}</h3>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusBadgeClass(event.status)}`}>
                {event.status}
              </span>
            </div>
            <p className="text-gray-600 mt-2">{event.description}</p>
            {event.privateDetails && (
              <div className="mt-4 p-3 bg-green-50 rounded-md">
                <h4 className="text-sm font-medium text-green-800">Private Details</h4>
                <p className="text-sm text-green-700">{event.privateDetails}</p>
              </div>
            )}
            <p className="text-sm text-gray-500 mt-2">
              {new Date(event.date).toLocaleString()}
            </p>
            <div className="mt-4">
              {event.status === 'creator' ? (
                <Link 
                  to={`/events/manage/${event.id}`}
                  className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  Manage Applications
                </Link>
              ) : (
                <button
                  onClick={() => handleApply(event.id)}
                  disabled={event.status !== 'not_applied'}
                  className={`inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white
                    ${event.status === 'not_applied' 
                      ? 'bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
                      : 'bg-gray-400 cursor-not-allowed'}`}
                >
                  {event.status === 'not_applied' ? 'Apply' : event.status}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
} 