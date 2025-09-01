import React, { useState } from 'react';
import { Search, MapPin, Calendar, User, X } from 'lucide-react';
import { siteConfig } from '../config/siteData';

interface TripLookupProps {
  onClose: () => void;
}

const TripLookup: React.FC<TripLookupProps> = ({ onClose }) => {
  const [tripId, setTripId] = useState('');
  const [tripDetails, setTripDetails] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!tripId.trim()) {
      setError('Please enter a trip ID');
      return;
    }

    setLoading(true);
    setError('');
    setTripDetails(null);

    try {
      // Make API call to get booking by trip ID
      const response = await fetch(`http://localhost:5000/api/bookings/trip/${tripId.trim()}`);
      
      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Trip not found. Please check your trip ID and try again.');
        }
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to fetch trip details');
      }

      const data = await response.json();
      const booking = data.booking;
      
      // Transform API response to match expected format
      const transformedBooking = {
        tripId: booking.trip_id,
        vehicleName: booking.vehicle_name,
        customerName: booking.customer_name,
        fromDate: new Date(booking.from_date).toLocaleDateString(),
        toDate: new Date(booking.to_date).toLocaleDateString(),
        pickupLocation: booking.pickup_location || 'Not specified',
        dropoffLocation: booking.dropoff_location || 'Not specified',
        totalFare: booking.total_fare,
        status: booking.status,
        paymentMethod: booking.payment_method
      };
      
      setTripDetails(transformedBooking);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch trip details');
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = async () => {
    if (!tripDetails || !confirm('Are you sure you want to cancel this booking?')) {
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await fetch(`http://localhost:5000/api/bookings/trip/${tripDetails.tripId}/cancel`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to cancel booking');
      }

      // Update trip details to show cancelled status
      setTripDetails({
        ...tripDetails,
        status: 'cancelled'
      });

      // Show success message
      alert('Booking cancelled successfully!');

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to cancel booking');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-2xl shadow-xl p-6 w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold text-gray-900">Manage Your Trip</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <form onSubmit={handleLookup} className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-3.5 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Enter your Trip ID (e.g., TRIP123456)"
              value={tripId}
              onChange={(e) => setTripId(e.target.value)}
              className="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full mt-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium py-3 px-4 rounded-lg transition-colors"
          >
            {loading ? 'Looking up...' : 'Find Trip'}
          </button>
        </form>

        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4">
            {error}
          </div>
        )}

        {tripDetails && (
          <div className="bg-gray-50 rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="font-semibold text-gray-900">Trip Details</h4>
              <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                tripDetails.status === 'confirmed' 
                  ? 'bg-green-100 text-green-700'
                  : 'bg-gray-100 text-gray-700'
              }`}>
                {tripDetails.status.charAt(0).toUpperCase() + tripDetails.status.slice(1)}
              </span>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2">
                <User className="h-4 w-4 text-gray-400" />
                <span>{tripDetails.customerName}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-gray-600">Vehicle:</span>
                <span>{tripDetails.vehicleName}</span>
              </div>
              <div className="flex items-center gap-2">
                <Calendar className="h-4 w-4 text-gray-400" />
                <span>{tripDetails.fromDate} to {tripDetails.toDate}</span>
              </div>
              <div className="flex items-center gap-2">
                <MapPin className="h-4 w-4 text-gray-400" />
                <span>{tripDetails.pickupLocation} → {tripDetails.dropoffLocation}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-gray-600">Total:</span>
                <span className="font-semibold">{siteConfig.currency.symbol}{tripDetails.totalFare.toLocaleString()}</span>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t">
              {tripDetails.status === 'cancelled' ? (
                <div className="w-full bg-gray-100 text-gray-500 py-2 px-4 rounded-lg text-center">
                  Booking Cancelled
                </div>
              ) : tripDetails.status === 'completed' ? (
                <div className="w-full bg-green-100 text-green-600 py-2 px-4 rounded-lg text-center">
                  Trip Completed
                </div>
              ) : (
                <button
                  onClick={handleCancel}
                  disabled={loading}
                  className="w-full bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-white py-2 px-4 rounded-lg transition-colors"
                >
                  {loading ? 'Cancelling...' : 'Cancel Booking'}
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TripLookup;