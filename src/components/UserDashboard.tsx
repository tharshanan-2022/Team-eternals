import React, { useState, useEffect } from 'react';
import { User, Calendar, Car, TrendingUp, Clock, MapPin, Phone, Mail, Edit3, LogOut, Eye, X } from 'lucide-react';
import { BookingDetails, Vehicle, User as UserType } from '../types';

interface DashboardStats {
  total_bookings: number;
  confirmed_bookings: number;
  completed_bookings: number;
  cancelled_bookings: number;
  total_spent: number;
}

interface BookingWithVehicle extends BookingDetails {
  id: string;
  trip_id: string;
  vehicle_name: string;
  vehicle_type: string;
  vehicle_image: string;
  status: 'confirmed' | 'completed' | 'cancelled';
  created_at: string;
}

interface MonthlyTrend {
  month: string;
  bookings: number;
  revenue: number;
}

interface DashboardData {
  user: UserType;
  stats: DashboardStats;
  recentBookings: BookingWithVehicle[];
  upcomingBookings: BookingWithVehicle[];
  monthlyTrend: MonthlyTrend[];
}

interface UserDashboardProps {
  user: UserType;
  onLogout: () => void;
  onClose: () => void;
}

const UserDashboard: React.FC<UserDashboardProps> = ({ user, onLogout, onClose }) => {
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'bookings' | 'profile'>('overview');
  const [allBookings, setAllBookings] = useState<BookingWithVehicle[]>([]);
  const [bookingsLoading, setBookingsLoading] = useState(false);
  const [selectedBooking, setSelectedBooking] = useState<BookingWithVehicle | null>(null);
  const [profileData, setProfileData] = useState({
    name: user.name,
    phone: user.phone
  });
  const [isEditingProfile, setIsEditingProfile] = useState(false);

  const API_BASE_URL = 'http://localhost:5000/api';

  // Get auth token from localStorage
  const getAuthToken = () => {
    return localStorage.getItem('taxi_booking_token');
  };

  // API call helper
  const apiCall = async (endpoint: string, options: RequestInit = {}) => {
    const token = getAuthToken();
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'API request failed');
    }

    return response.json();
  };

  // Load dashboard data
  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const data = await apiCall(`/users/${user.id}/dashboard`);
      setDashboardData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  // Load all bookings
  const loadAllBookings = async () => {
    try {
      setBookingsLoading(true);
      const data = await apiCall(`/users/${user.id}/bookings?limit=50`);
      setAllBookings(data.bookings);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load bookings');
    } finally {
      setBookingsLoading(false);
    }
  };

  // Cancel booking
  const cancelBooking = async (bookingId: string) => {
    try {
      await apiCall(`/users/${user.id}/bookings/${bookingId}/cancel`, {
        method: 'PUT'
      });
      
      // Refresh data
      await loadDashboardData();
      if (activeTab === 'bookings') {
        await loadAllBookings();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to cancel booking');
    }
  };

  // Update profile
  const updateProfile = async () => {
    try {
      await apiCall(`/users/${user.id}/profile`, {
        method: 'PUT',
        body: JSON.stringify(profileData)
      });
      
      setIsEditingProfile(false);
      // Refresh dashboard data to get updated user info
      await loadDashboardData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update profile');
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, [user.id]);

  useEffect(() => {
    if (activeTab === 'bookings' && allBookings.length === 0) {
      loadAllBookings();
    }
  }, [activeTab]);

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-LK', {
      style: 'currency',
      currency: 'LKR'
    }).format(amount);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-IN', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'confirmed': return 'text-blue-600 bg-blue-100';
      case 'completed': return 'text-green-600 bg-green-100';
      case 'cancelled': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-8 max-w-md w-full mx-4">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
          <p className="text-center mt-4 text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-8 max-w-md w-full mx-4">
          <div className="text-center">
            <div className="text-red-600 text-xl mb-4">⚠️</div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Error</h3>
            <p className="text-gray-600 mb-4">{error}</p>
            <div className="flex gap-2 justify-center">
              <button
                onClick={() => {
                  setError(null);
                  loadDashboardData();
                }}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Retry
              </button>
              <button
                onClick={onClose}
                className="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!dashboardData) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-6xl h-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-blue-800 text-white p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-white bg-opacity-20 rounded-full flex items-center justify-center">
                <User className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-2xl font-bold">Welcome, {dashboardData.user.name}!</h1>
                <p className="text-blue-100">{dashboardData.user.email}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={onLogout}
                className="flex items-center gap-2 px-4 py-2 bg-white bg-opacity-20 rounded-lg hover:bg-opacity-30 transition-all"
              >
                <LogOut className="w-4 h-4" />
                Logout
              </button>
              <button
                onClick={onClose}
                className="p-2 bg-white bg-opacity-20 rounded-lg hover:bg-opacity-30 transition-all"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="border-b border-gray-200">
          <div className="flex">
            {[
              { id: 'overview', label: 'Overview', icon: TrendingUp },
              { id: 'bookings', label: 'My Bookings', icon: Calendar },
              { id: 'profile', label: 'Profile', icon: User }
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center gap-2 px-6 py-4 font-medium transition-all ${
                    activeTab === tab.id
                      ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Stats Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-gradient-to-r from-blue-500 to-blue-600 text-white p-6 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-blue-100">Total Bookings</p>
                      <p className="text-3xl font-bold">{dashboardData.stats.total_bookings}</p>
                    </div>
                    <Calendar className="w-8 h-8 text-blue-200" />
                  </div>
                </div>
                
                <div className="bg-gradient-to-r from-green-500 to-green-600 text-white p-6 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-green-100">Completed</p>
                      <p className="text-3xl font-bold">{dashboardData.stats.completed_bookings}</p>
                    </div>
                    <Car className="w-8 h-8 text-green-200" />
                  </div>
                </div>
                
                <div className="bg-gradient-to-r from-yellow-500 to-yellow-600 text-white p-6 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-yellow-100">Confirmed</p>
                      <p className="text-3xl font-bold">{dashboardData.stats.confirmed_bookings}</p>
                    </div>
                    <Clock className="w-8 h-8 text-yellow-200" />
                  </div>
                </div>
                
                <div className="bg-gradient-to-r from-purple-500 to-purple-600 text-white p-6 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-purple-100">Total Spent</p>
                      <p className="text-3xl font-bold">{formatCurrency(dashboardData.stats.total_spent)}</p>
                    </div>
                    <TrendingUp className="w-8 h-8 text-purple-200" />
                  </div>
                </div>
              </div>

              {/* Recent Bookings */}
              <div className="bg-white rounded-lg border border-gray-200">
                <div className="p-6 border-b border-gray-200">
                  <h2 className="text-xl font-semibold text-gray-900">Recent Bookings</h2>
                </div>
                <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                  {dashboardData.recentBookings.length > 0 ? (
                    dashboardData.recentBookings.map((booking) => (
                      <div key={booking.id} className="p-6 hover:bg-gray-50">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <div className="w-12 h-12 bg-gray-100 rounded-lg flex items-center justify-center">
                              <Car className="w-6 h-6 text-gray-600" />
                            </div>
                            <div>
                              <h3 className="font-semibold text-gray-900">{booking.vehicle_name}</h3>
                              <p className="text-sm text-gray-600">Trip ID: {booking.trip_id}</p>
                              <p className="text-sm text-gray-600">{formatDate(booking.from_date)}</p>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="font-semibold text-gray-900">{formatCurrency(booking.totalFare)}</p>
                            <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(booking.status)}`}>
                              {booking.status.charAt(0).toUpperCase() + booking.status.slice(1)}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="p-6 text-center text-gray-500">
                      No bookings found
                    </div>
                  )}
                </div>
              </div>

              {/* Upcoming Bookings */}
              {dashboardData.upcomingBookings.length > 0 && (
                <div className="bg-white rounded-lg border border-gray-200">
                  <div className="p-6 border-b border-gray-200">
                    <h2 className="text-xl font-semibold text-gray-900">Upcoming Bookings</h2>
                  </div>
                  <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                    {dashboardData.upcomingBookings.map((booking) => (
                      <div key={booking.id} className="p-6 hover:bg-gray-50">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                              <Car className="w-6 h-6 text-blue-600" />
                            </div>
                            <div>
                              <h3 className="font-semibold text-gray-900">{booking.vehicle_name}</h3>
                              <p className="text-sm text-gray-600">Trip ID: {booking.trip_id}</p>
                              <p className="text-sm text-gray-600">{formatDate(booking.from_date)}</p>
                              {booking.pickupLocation && (
                                <p className="text-sm text-gray-600 flex items-center gap-1">
                                  <MapPin className="w-3 h-3" />
                                  {booking.pickupLocation}
                                </p>
                              )}
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="font-semibold text-gray-900">{formatCurrency(booking.totalFare)}</p>
                            <button
                              onClick={() => cancelBooking(booking.id)}
                              className="mt-2 px-3 py-1 bg-red-100 text-red-600 rounded-lg text-sm hover:bg-red-200 transition-colors"
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'bookings' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold text-gray-900">All Bookings</h2>
              </div>
              
              {bookingsLoading ? (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                  <p className="mt-2 text-gray-600">Loading bookings...</p>
                </div>
              ) : (
                <div className="bg-white rounded-lg border border-gray-200">
                  <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                    {allBookings.length > 0 ? (
                      allBookings.map((booking) => (
                        <div key={booking.id} className="p-6 hover:bg-gray-50">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-4">
                              <div className="w-16 h-16 bg-gray-100 rounded-lg flex items-center justify-center">
                                <Car className="w-8 h-8 text-gray-600" />
                              </div>
                              <div>
                                <h3 className="font-semibold text-gray-900">{booking.vehicle_name}</h3>
                                <p className="text-sm text-gray-600">Trip ID: {booking.trip_id}</p>
                                <p className="text-sm text-gray-600">{formatDate(booking.from_date)} - {formatDate(booking.to_date)}</p>
                                {booking.pickupLocation && (
                                  <p className="text-sm text-gray-600 flex items-center gap-1 mt-1">
                                    <MapPin className="w-3 h-3" />
                                    {booking.pickupLocation}
                                    {booking.dropoffLocation && ` → ${booking.dropoffLocation}`}
                                  </p>
                                )}
                              </div>
                            </div>
                            <div className="text-right">
                              <p className="font-semibold text-gray-900">{formatCurrency(booking.totalFare)}</p>
                              <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium mt-1 ${getStatusColor(booking.status)}`}>
                                {booking.status.charAt(0).toUpperCase() + booking.status.slice(1)}
                              </span>
                              <div className="mt-2 flex gap-2">
                                <button
                                  onClick={() => setSelectedBooking(booking)}
                                  className="px-3 py-1 bg-blue-100 text-blue-600 rounded-lg text-sm hover:bg-blue-200 transition-colors flex items-center gap-1"
                                >
                                  <Eye className="w-3 h-3" />
                                  View
                                </button>
                                {booking.status === 'confirmed' && new Date(booking.from_date) > new Date() && (
                                  <button
                                    onClick={() => cancelBooking(booking.id)}
                                    className="px-3 py-1 bg-red-100 text-red-600 rounded-lg text-sm hover:bg-red-200 transition-colors"
                                  >
                                    Cancel
                                  </button>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="p-8 text-center text-gray-500">
                        <Calendar className="w-12 h-12 text-gray-300 mx-auto mb-4" />
                        <p>No bookings found</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'profile' && (
            <div className="space-y-6">
              <div className="bg-white rounded-lg border border-gray-200 p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-2xl font-bold text-gray-900">Profile Information</h2>
                  <button
                    onClick={() => setIsEditingProfile(!isEditingProfile)}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    <Edit3 className="w-4 h-4" />
                    {isEditingProfile ? 'Cancel' : 'Edit'}
                  </button>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      <User className="w-4 h-4 inline mr-2" />
                      Full Name
                    </label>
                    {isEditingProfile ? (
                      <input
                        type="text"
                        value={profileData.name}
                        onChange={(e) => setProfileData({ ...profileData, name: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    ) : (
                      <p className="text-gray-900">{dashboardData.user.name}</p>
                    )}
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      <Mail className="w-4 h-4 inline mr-2" />
                      Email Address
                    </label>
                    <p className="text-gray-900">{dashboardData.user.email}</p>
                    <p className="text-xs text-gray-500 mt-1">Email cannot be changed</p>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      <Phone className="w-4 h-4 inline mr-2" />
                      Phone Number
                    </label>
                    {isEditingProfile ? (
                      <input
                        type="tel"
                        value={profileData.phone}
                        onChange={(e) => setProfileData({ ...profileData, phone: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      />
                    ) : (
                      <p className="text-gray-900">{dashboardData.user.phone}</p>
                    )}
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      <Calendar className="w-4 h-4 inline mr-2" />
                      Member Since
                    </label>
                    <p className="text-gray-900">{formatDate(dashboardData.user.created_at)}</p>
                  </div>
                </div>
                
                {isEditingProfile && (
                  <div className="mt-6 flex gap-3">
                    <button
                      onClick={updateProfile}
                      className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                    >
                      Save Changes
                    </button>
                    <button
                      onClick={() => {
                        setIsEditingProfile(false);
                        setProfileData({ name: user.name, phone: user.phone });
                      }}
                      className="px-6 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400 transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Booking Details Modal */}
      {selectedBooking && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-60 p-4">
          <div className="bg-white rounded-lg max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <h3 className="text-xl font-semibold text-gray-900">Booking Details</h3>
                <button
                  onClick={() => setSelectedBooking(null)}
                  className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Trip ID</label>
                  <p className="text-gray-900">{selectedBooking.trip_id}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Status</label>
                  <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(selectedBooking.status)}`}>
                    {selectedBooking.status.charAt(0).toUpperCase() + selectedBooking.status.slice(1)}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Vehicle</label>
                  <p className="text-gray-900">{selectedBooking.vehicle_name}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Rental Type</label>
                  <p className="text-gray-900 capitalize">{selectedBooking.rentalType}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">From Date</label>
                  <p className="text-gray-900">{formatDate(selectedBooking.from_date)}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">To Date</label>
                  <p className="text-gray-900">{formatDate(selectedBooking.to_date)}</p>
                </div>
                {selectedBooking.pickupLocation && (
                  <div className="col-span-2">
                    <label className="block text-sm font-medium text-gray-700">Pickup Location</label>
                    <p className="text-gray-900">{selectedBooking.pickupLocation}</p>
                  </div>
                )}
                {selectedBooking.dropoffLocation && (
                  <div className="col-span-2">
                    <label className="block text-sm font-medium text-gray-700">Dropoff Location</label>
                    <p className="text-gray-900">{selectedBooking.dropoffLocation}</p>
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-700">Payment Method</label>
                  <p className="text-gray-900 capitalize">{selectedBooking.paymentMethod}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Total Fare</label>
                  <p className="text-gray-900 font-semibold">{formatCurrency(selectedBooking.totalFare)}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserDashboard;