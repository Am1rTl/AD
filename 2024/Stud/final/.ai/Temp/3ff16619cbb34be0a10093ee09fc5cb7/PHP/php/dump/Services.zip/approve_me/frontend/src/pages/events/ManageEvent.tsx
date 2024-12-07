import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import client from '../../api/client';
import LoadingSpinner from '../../components/LoadingSpinner';
import { FaSnowflake, FaUserFriends, FaCheck, FaTimes, FaCalendarAlt, FaFileExport, FaFileImport } from 'react-icons/fa';
import { GiPartyPopper } from 'react-icons/gi';
import Snowfall from '../../components/Snowfall';

interface Participant {
  id: number;
  userId: number;
  eventId: number;
  status: 'pending' | 'approved' | 'rejected';
  User: {
    name: string;
    email: string;
  };
}

interface Event {
  id: number;
  title: string;
  description: string;
  privateDetails?: string;
  date: string;
  creatorId: number;
}

export default function ManageEvent() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [event, setEvent] = useState<Event | null>(null);
  const [participants, setParticipants] = useState<Participant[]>([]);
  const [loading, setLoading] = useState(true);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importError, setImportError] = useState('');

  useEffect(() => {
    loadEventAndParticipants();
  }, [id]);

  const loadEventAndParticipants = async () => {
    try {
      const [eventResponse, participantsResponse] = await Promise.all([
        client.get(`/events/${id}`),
        client.get(`/events/${id}/participations`)
      ]);
      
      setEvent(eventResponse.data);
      setParticipants(participantsResponse.data);
    } catch (error) {
      console.error('Error loading event details:', error);
      navigate('/events');
    } finally {
      setLoading(false);
    }
  };

  const handleStatusUpdate = async (participationId: number, newStatus: 'approved' | 'rejected') => {
    try {
      await client.put(`/events/${id}/participations/${participationId}`, {
        status: newStatus
      });
      
      setParticipants(participants.map(participant =>
        participant.id === participationId
          ? { ...participant, status: newStatus }
          : participant
      ));
    } catch (error) {
      console.error('Error updating participation status:', error);
    }
  };

  const handleExport = async () => {
    if (!event) return;
    try {
      const response = await client.get(`/events/${event.id}/export`);
      // Create and download export file
      const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `event-${event.id}-export.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportFile(file);
  };

  const handleImportSubmit = async () => {
    if (!importFile) return;
    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const content = JSON.parse(e.target?.result as string);
          await client.post('/events/import', content);
          navigate('/events');
        } catch (error) {
          setImportError('Invalid import file format');
        }
      };
      reader.readAsText(importFile);
    } catch (error) {
      setImportError('Import failed');
    }
  };

  if (loading) return <LoadingSpinner />;
  if (!event) return <LoadingSpinner />;

  return (
    <div className="space-y-6 relative">
      <Snowfall />
      
      <div className="card">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="festive-header flex items-center gap-2">
              {event.title}
            </h1>
            <p className="text-gray-600 mt-4">{event.description}</p>
          </div>
          <FaSnowflake className="text-3xl text-emerald-200 animate-spin-slow" />
        </div>
        
        {event.privateDetails && (
          <div className="mt-4 p-4 bg-emerald-50 rounded-md border border-emerald-200">
            <h4 className="text-sm font-medium text-emerald-800 flex items-center gap-2">
              <GiPartyPopper className="text-emerald-600" />
              Private Details
            </h4>
            <p className="text-sm text-emerald-700 mt-1">{event.privateDetails}</p>
          </div>
        )}
        
        <p className="text-sm text-gray-500 mt-4 flex items-center gap-2">
          <FaCalendarAlt className="text-emerald-500" />
          {new Date(event.date).toLocaleString()}
        </p>

        <div className="flex gap-4 mt-6">
          <button
            onClick={handleExport}
            className="btn btn-secondary flex items-center gap-2"
          >
            <FaFileExport />
            Export Event
          </button>

          <div className="relative">
            <input
              type="file"
              accept=".json"
              onChange={handleImport}
              className="hidden"
              id="import-file"
            />
            <label
              htmlFor="import-file"
              className="btn btn-secondary flex items-center gap-2 cursor-pointer"
            >
              <FaFileImport />
              Import Event
            </label>
          </div>
        </div>

        {importFile && (
          <div className="mt-4">
            <p className="text-sm text-emerald-600">
              Selected file: {importFile.name}
            </p>
            <button
              onClick={handleImportSubmit}
              className="btn btn-primary mt-2"
            >
              Process Import
            </button>
          </div>
        )}

        {importError && (
          <div className="mt-4 text-red-600 text-sm">
            {importError}
          </div>
        )}
      </div>

      <div className="card">
        <div className="flex items-center gap-2 mb-6">
          <FaUserFriends className="text-2xl text-emerald-600" />
          <h2 className="text-xl font-semibold text-emerald-800">Applications</h2>
        </div>
        
        {participants.length === 0 ? (
          <div className="text-center py-8">
            <FaSnowflake className="text-5xl text-emerald-200 mx-auto mb-3 animate-spin-slow" />
            <p className="text-gray-500">No applications yet.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-emerald-200">
              <thead className="bg-emerald-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Email
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-emerald-100">
                {participants.map((participant) => (
                  <tr key={participant.id} className="hover:bg-emerald-50 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap">
                      {participant.User?.name || 'Unknown User'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {participant.User?.email || 'No email'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium
                        ${participant.status === 'approved' ? 'bg-emerald-100 text-emerald-800' : 
                          participant.status === 'rejected' ? 'bg-red-100 text-red-800' : 
                          'bg-yellow-100 text-yellow-800'}`}>
                        {participant.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                      {participant.status === 'pending' && (
                        <>
                          <button
                            onClick={() => handleStatusUpdate(participant.id, 'approved')}
                            className="text-emerald-600 hover:text-emerald-900 flex items-center gap-1"
                          >
                            <FaCheck /> Approve
                          </button>
                          <button
                            onClick={() => handleStatusUpdate(participant.id, 'rejected')}
                            className="text-red-600 hover:text-red-900 flex items-center gap-1"
                          >
                            <FaTimes /> Reject
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
} 