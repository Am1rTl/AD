import { FaSnowflake } from 'react-icons/fa';

export default function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center min-h-[200px]">
      <FaSnowflake className="text-4xl text-emerald-500 animate-spin" />
    </div>
  );
} 