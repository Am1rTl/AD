import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FaFileImport, FaCode } from 'react-icons/fa';
import client from '../../api/client';

export default function BulkImport() {
  const navigate = useNavigate();
  const [files, setFiles] = useState<FileList | null>(null);
  const [template, setTemplate] = useState('');
  const [error, setError] = useState('');

  const handleImport = async () => {
    if (!files) return;

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const reader = new FileReader();
        
        await new Promise((resolve, reject) => {
          reader.onload = async (e) => {
            try {
              const content = JSON.parse(e.target?.result as string);
              // Add custom import template if provided
              if (template) {
                content.importTemplate = template;
              }
              await client.post('/events/import', content);
              resolve(null);
            } catch (error) {
              reject(error);
            }
          };
          reader.onerror = reject;
          reader.readAsText(file);
        });
      }
      
      navigate('/events');
    } catch (error) {
      setError('Import failed. Please check your files and template.');
    }
  };

  return (
    <div className="card max-w-2xl mx-auto">
      <h1 className="festive-header flex items-center gap-2">
        <FaFileImport className="text-emerald-600" />
        Bulk Import Events
      </h1>

      <div className="mt-6 space-y-6">
        <div>
          <label className="block text-sm font-medium text-emerald-800 mb-2">
            Select Event Files
          </label>
          <input
            type="file"
            accept=".json"
            multiple
            onChange={(e) => setFiles(e.target.files)}
            className="block w-full text-sm text-gray-500
              file:mr-4 file:py-2 file:px-4
              file:rounded-full file:border-0
              file:text-sm file:font-semibold
              file:bg-emerald-50 file:text-emerald-700
              hover:file:bg-emerald-100"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-emerald-800 mb-2 flex items-center gap-2">
            <FaCode />
            Custom Import Template (Optional)
          </label>
          <textarea
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            placeholder="function processImport(data) { return data; }"
            className="input min-h-[200px] font-mono text-sm"
          />
          <p className="mt-1 text-xs text-gray-500">
            Add custom JavaScript to process your imports. The template must define a processImport function.
          </p>
        </div>

        {error && (
          <div className="text-red-600 text-sm">
            {error}
          </div>
        )}

        <button
          onClick={handleImport}
          disabled={!files}
          className="btn btn-primary w-full"
        >
          Import Events
        </button>
      </div>
    </div>
  );
} 