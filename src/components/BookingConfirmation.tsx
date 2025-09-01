import React from 'react';
import { CheckCircle, Download, Share2, Calendar, MapPin, User } from 'lucide-react';
import { BookingDetails, Vehicle } from '../types';
import { siteConfig } from '../config/siteData';

interface BookingConfirmationProps {
  booking: BookingDetails & { tripId: string };
  vehicle: Vehicle;
  onNewBooking: () => void;
}

const BookingConfirmation: React.FC<BookingConfirmationProps> = ({
  booking,
  vehicle,
  onNewBooking,
}) => {
  return (
    <div className="max-w-2xl mx-auto">
      <div className="bg-white rounded-2xl shadow-lg p-8 text-center">
        <div className="mb-6">
          <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
          <h2 className="text-3xl font-bold text-gray-900 mb-2">
            Booking Confirmed!
          </h2>
          <p className="text-gray-600">
            Your vehicle has been successfully booked. Save your Trip ID for future reference.
          </p>
        </div>

        <div className="bg-blue-50 rounded-xl p-6 mb-6">
          <div className="text-center mb-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Trip ID</h3>
            <div className="text-2xl font-bold text-blue-600 bg-white rounded-lg py-3 px-6 inline-block">
              {booking.tripId}
            </div>
            <p className="text-sm text-gray-600 mt-2">
              Keep this ID safe. You'll need it to manage your booking.
            </p>
          </div>
        </div>

        <div className="text-left space-y-4 mb-6">
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold text-gray-900 mb-3">Vehicle Details</h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <img
                    src={vehicle.image}
                    alt={vehicle.name}
                    className="w-8 h-8 rounded object-cover"
                  />
                  <span>{vehicle.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Calendar className="h-4 w-4 text-gray-400" />
                  <span>{booking.fromDate.toLocaleDateString()} - {booking.toDate.toLocaleDateString()}</span>
                </div>
                {booking.rentalType === 'location' && (
                  <>
                    <div className="flex items-center gap-2">
                      <MapPin className="h-4 w-4 text-gray-400" />
                      <span>From: {booking.pickupLocation}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <MapPin className="h-4 w-4 text-gray-400" />
                      <span>To: {booking.dropoffLocation}</span>
                    </div>
                  </>
                )}
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-gray-900 mb-3">Customer Details</h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <User className="h-4 w-4 text-gray-400" />
                  <span>{booking.customerName}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-600">Email:</span>
                  <span>{booking.customerEmail}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-600">Phone:</span>
                  <span>{booking.customerPhone}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-600">Total:</span>
                  <span className="font-semibold">{siteConfig.currency.symbol}{booking.totalFare.toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <button className="flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg transition-colors">
            <Download className="h-5 w-5" />
            Download Receipt
          </button>
          <button className="flex items-center justify-center gap-2 bg-gray-100 hover:bg-gray-200 text-gray-900 px-6 py-3 rounded-lg transition-colors">
            <Share2 className="h-5 w-5" />
            Share Trip ID
          </button>
        </div>

        <div className="mt-8 pt-6 border-t">
          <button
            onClick={onNewBooking}
            className="text-blue-600 hover:text-blue-700 font-medium"
          >
            Book Another Vehicle
          </button>
        </div>
      </div>
    </div>
  );
};

export default BookingConfirmation;