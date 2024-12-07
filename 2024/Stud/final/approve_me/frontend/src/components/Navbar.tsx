import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { FaSnowflake, FaSignOutAlt, FaUser, FaGift } from 'react-icons/fa';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await logout();
      navigate('/login');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  return (
    <nav className="bg-gradient-to-r from-emerald-600 to-emerald-800 shadow-lg relative">
      <div className="absolute inset-0 overflow-hidden pointer-events-none z-0">
        {/* Decorative snowflakes */}
        <div className="absolute top-1 left-4 text-emerald-300/30 text-xl">
          <FaSnowflake className="animate-spin-slow" />
        </div>
        <div className="absolute top-2 right-8 text-emerald-300/30 text-sm">
          <FaSnowflake className="animate-spin-slow" style={{ animationDuration: '4s' }} />
        </div>
        <div className="absolute bottom-1 left-1/4 text-emerald-300/30 text-lg">
          <FaSnowflake className="animate-spin-slow" style={{ animationDuration: '6s' }} />
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <Link 
              to="/" 
              className="flex items-center gap-2 text-white font-bold text-xl hover:text-emerald-100 transition-colors"
            >
              <FaGift className="text-2xl" />
              <span>Holiday Events</span>
            </Link>
          </div>

          <div className="flex items-center gap-6">
            {user ? (
              <>
                <div className="flex items-center gap-2 text-emerald-100">
                  <FaUser className="text-emerald-200" />
                  <span>{user.name}</span>
                </div>
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-2 px-4 py-2 rounded-md bg-emerald-700 text-white hover:bg-emerald-600 transition-colors duration-200"
                >
                  <FaSignOutAlt />
                  <span>Sign Out</span>
                </button>
              </>
            ) : (
              <div className="space-x-4">
                <Link
                  to="/login"
                  className="text-emerald-100 hover:text-white transition-colors duration-200"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="px-4 py-2 rounded-md bg-emerald-700 text-white hover:bg-emerald-600 transition-colors duration-200"
                >
                  Register
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Decorative bottom border */}
      <div className="h-1 bg-gradient-to-r from-emerald-200/20 via-emerald-100/40 to-emerald-200/20" />
    </nav>
  );
}