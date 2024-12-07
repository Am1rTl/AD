import { useEffect, useState } from 'react';
import { FaSnowflake } from 'react-icons/fa';

interface Snowflake {
  id: number;
  left: number;
  size: number;
  delay: number;
  duration: number;
  opacity: number;
}

export default function Snowfall() {
  const [snowflakes, setSnowflakes] = useState<Snowflake[]>([]);

  useEffect(() => {
    const flakes = Array.from({ length: 30 }, (_, i) => ({
      id: i,
      left: Math.random() * 100,
      size: Math.random() * 1 + 1, // 1 to 2 rem (doubled size)
      delay: Math.random() * 10,
      duration: Math.random() * 5 + 10, // 10 to 15 seconds
      opacity: Math.random() * 0.3 + 0.6, // 0.6 to 0.9 (increased opacity)
    }));
    setSnowflakes(flakes);
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
      {snowflakes.map(flake => (
        <div
          key={flake.id}
          className="absolute animate-fall"
          style={{
            left: `${flake.left}%`,
            fontSize: `${flake.size}rem`,
            opacity: flake.opacity,
            animationDelay: `${flake.delay}s`,
            animationDuration: `${flake.duration}s`,
            transform: `translateY(-20px) rotate(0deg)`,
          }}
        >
          <FaSnowflake className="text-emerald-200" />
        </div>
      ))}
    </div>
  );
} 