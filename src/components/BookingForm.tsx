import React, { useState, useEffect } from 'react';
import { User, Phone, Mail, MapPin, Clock, CreditCard, Banknote, Wallet, ArrowLeft, CheckCircle, Home, UserCheck, AlertCircle, FileText } from 'lucide-react';
import { Vehicle, RentalType, PaymentMethod, BookingDetails } from '../types';
import { calculateFare } from '../utils/pricing';
import { siteConfig } from '../config/siteData';

interface BookingFormProps {
  vehicle: Vehicle;
  rentalType: RentalType;
  fromDate: Date;
  toDate: Date;
  onBookingComplete: (booking: BookingDetails & { tripId: string }) => void;
  onBack: () => void;
}

const BookingForm: React.FC<BookingFormProps> = ({
  vehicle,
  rentalType,
  fromDate,
  toDate,
  onBookingComplete,
  onBack,
}) => {
  const [formData, setFormData] = useState({
    customerName: '',
    customerEmail: '',
    customerPhone: '',
    customerAddress: '',
    emergencyContactName: '',
    emergencyContactPhone: '',
    idType: 'passport',
    idNumber: '',
    specialRequirements: '',
    pickupLocation: '',
    dropoffLocation: '',
    distance: 10,
    hours: 4,
    days: 1,
    paymentMethod: 'cash' as PaymentMethod,
    isGuest: true,
    agreeToTerms: false,
  });

  const [totalFare, setTotalFare] = useState(0);
  const [walletBalance, setWalletBalance] = useState(0);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    let duration = 0;
    let distance = 0;

    switch (rentalType) {
      case 'hourly':
        duration = formData.hours;
        break;
      case 'daily':
        duration = formData.days;
        break;
      case 'location':
        distance = formData.distance;
        break;
    }

    const fare = calculateFare(vehicle, rentalType, duration, distance);
    setTotalFare(fare);
  }, [vehicle, rentalType, formData.hours, formData.days, formData.distance]);

  // Fetch wallet balance when component mounts
  useEffect(() => {
    const fetchWalletBalance = async () => {
      const token = localStorage.getItem('taxi_booking_token');
      if (token) {
        try {
          const response = await fetch('http://localhost:5000/api/wallet/balance', {
            headers: {
              Authorization: `Bearer ${token}`
            }
          });
          if (response.ok) {
            const data = await response.json();
            setWalletBalance(data.balance || 0);
          }
        } catch (error) {
          console.error('Failed to fetch wallet balance:', error);
        }
      }
    };
    fetchWalletBalance();
  }, []);

  const [errors, setErrors] = useState<Record<string, string>>({});

  const validateForm = () => {
    const newErrors: Record<string, string> = {};
    
    if (!formData.customerName.trim()) {
      newErrors.customerName = 'Full name is required';
    }
    if (!formData.customerEmail.trim()) {
      newErrors.customerEmail = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.customerEmail)) {
      newErrors.customerEmail = 'Please enter a valid email address';
    }
    if (!formData.customerPhone.trim()) {
      newErrors.customerPhone = 'Phone number is required';
    } else if (!/^[\+]?[1-9][\d]{0,15}$/.test(formData.customerPhone.replace(/\s/g, ''))) {
      newErrors.customerPhone = 'Please enter a valid phone number';
    }
    if (!formData.customerAddress.trim()) {
      newErrors.customerAddress = 'Address is required';
    }
    if (!formData.emergencyContactName.trim()) {
      newErrors.emergencyContactName = 'Emergency contact name is required';
    }
    if (!formData.emergencyContactPhone.trim()) {
      newErrors.emergencyContactPhone = 'Emergency contact phone is required';
    }
    if (!formData.idNumber.trim()) {
      newErrors.idNumber = 'ID number is required';
    }
    if (!formData.agreeToTerms) {
      newErrors.agreeToTerms = 'You must agree to the terms and conditions';
    }
    if (rentalType === 'location' && !formData.pickupLocation.trim()) {
      newErrors.pickupLocation = 'Pickup location is required';
    }
    if (rentalType === 'location' && !formData.dropoffLocation.trim()) {
      newErrors.dropoffLocation = 'Drop-off location is required';
    }
    
    // Check wallet balance if wallet payment is selected
    if (formData.paymentMethod === 'wallet' && walletBalance < totalFare) {
      newErrors.paymentMethod = `Insufficient wallet balance. You have Rs.${walletBalance.toFixed(2)} but need Rs.${totalFare.toFixed(2)}`;
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);

    try {
      // Get auth token if available
      const token = localStorage.getItem('taxi_booking_token');
      
      // Process wallet payment if wallet is selected
      if (formData.paymentMethod === 'wallet' && token) {
        const walletPaymentResponse = await fetch('http://localhost:5000/api/wallet/pay', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify({
            amount: totalFare,
            description: `Vehicle booking - ${vehicle.name}`,
            bookingDetails: {
              vehicleId: vehicle.id,
              rentalType,
              fromDate: fromDate.toISOString(),
              toDate: toDate.toISOString()
            }
          })
        });
        
        if (!walletPaymentResponse.ok) {
          const errorData = await walletPaymentResponse.json();
          throw new Error(errorData.message || 'Wallet payment failed');
        }
        
        // Update wallet balance after successful payment
        setWalletBalance(prev => prev - totalFare);
      }
      
      // Prepare booking data for API
      const bookingPayload = {
        vehicleId: vehicle.id,
        rentalType,
        fromDate: fromDate.toISOString(),
        toDate: toDate.toISOString(),
        pickupLocation: rentalType === 'location' ? formData.pickupLocation : undefined,
        dropoffLocation: rentalType === 'location' ? formData.dropoffLocation : undefined,
        hours: rentalType === 'hourly' ? formData.hours : undefined,
        days: rentalType === 'daily' ? formData.days : undefined,
        totalFare,
        paymentMethod: formData.paymentMethod,
        customerName: formData.customerName,
        customerEmail: formData.customerEmail,
        customerPhone: formData.customerPhone
      };

      // Make API call to create booking
      const response = await fetch('http://localhost:5000/api/bookings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token && { Authorization: `Bearer ${token}` })
        },
        body: JSON.stringify(bookingPayload)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Booking failed');
      }

      const result = await response.json();
      const booking = result.booking;
      
      // Transform API response to match expected format
      const bookingData: BookingDetails & { tripId: string } = {
        tripId: booking.trip_id,
        vehicleId: booking.vehicle_id,
        rentalType: booking.rental_type,
        fromDate,
        toDate,
        pickupLocation: booking.pickup_location,
        dropoffLocation: booking.dropoff_location,
        hours: booking.hours,
        days: booking.days,
        totalFare: booking.total_fare,
        paymentMethod: booking.payment_method as PaymentMethod,
        customerName: booking.customer_name,
        customerEmail: booking.customer_email,
        customerPhone: booking.customer_phone,
        isGuest: booking.is_guest
      };
      
      onBookingComplete(bookingData);
    } catch (error) {
      console.error('Booking failed:', error);
      alert(error instanceof Error ? error.message : 'Booking failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-white rounded-2xl shadow-lg p-8 border border-gray-100 animate-fade-in">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h3 className="text-3xl font-bold bg-gradient-to-r from-gray-900 to-gray-700 bg-clip-text text-transparent mb-2">
            Complete Your Booking
          </h3>
          <p className="text-gray-600">Fill in the details to confirm your reservation</p>
        </div>
        <button
          onClick={onBack}
          className="group flex items-center gap-2 px-4 py-2 text-primary-600 hover:text-primary-700 font-medium bg-primary-50 hover:bg-primary-100 rounded-lg transition-all duration-300 hover:scale-105"
        >
          <ArrowLeft className="h-4 w-4 transition-transform group-hover:-translate-x-1" />
          Back to Vehicles
        </button>
      </div>

      <div className="grid md:grid-cols-2 gap-8">
        {/* Booking Form */}
        <div className="animate-slide-up" style={{animationDelay: '0.1s'}}>
          <form onSubmit={handleSubmit} className="space-y-8">
            <div className="bg-gradient-to-br from-blue-50 to-indigo-50 p-6 rounded-xl border border-blue-100">
              <h4 className="text-xl font-semibold text-gray-900 mb-6 flex items-center gap-2">
                <div className="w-8 h-8 bg-primary-600 rounded-lg flex items-center justify-center">
                  <User className="h-4 w-4 text-white" />
                </div>
                Customer Details
              </h4>
              
              <div className="space-y-6">
                {/* Basic Information */}
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="relative group">
                    <User className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                    <input
                      type="text"
                      placeholder="Full Name *"
                      value={formData.customerName}
                      onChange={(e) => setFormData({ ...formData, customerName: e.target.value })}
                      className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 ${
                        errors.customerName ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                      }`}
                      required
                    />
                    {errors.customerName && (
                      <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                        <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                        {errors.customerName}
                      </p>
                    )}
                  </div>
                  
                  <div className="relative group">
                    <Phone className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                    <input
                      type="tel"
                      placeholder="Phone Number *"
                      value={formData.customerPhone}
                      onChange={(e) => setFormData({ ...formData, customerPhone: e.target.value })}
                      className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 ${
                        errors.customerPhone ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                      }`}
                      required
                    />
                    {errors.customerPhone && (
                      <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                        <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                        {errors.customerPhone}
                      </p>
                    )}
                  </div>
                </div>
                
                <div className="relative group">
                  <Mail className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                  <input
                    type="email"
                    placeholder="Email Address *"
                    value={formData.customerEmail}
                    onChange={(e) => setFormData({ ...formData, customerEmail: e.target.value })}
                    className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 ${
                      errors.customerEmail ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                    }`}
                    required
                  />
                  {errors.customerEmail && (
                    <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                      <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                      {errors.customerEmail}
                    </p>
                  )}
                </div>
                
                <div className="relative group">
                  <Home className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                  <textarea
                    placeholder="Full Address *"
                    value={formData.customerAddress}
                    onChange={(e) => setFormData({ ...formData, customerAddress: e.target.value })}
                    rows={3}
                    className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 resize-none ${
                      errors.customerAddress ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                    }`}
                    required
                  />
                  {errors.customerAddress && (
                    <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                      <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                      {errors.customerAddress}
                    </p>
                  )}
                </div>
                
                {/* Emergency Contact */}
                <div className="border-t border-gray-200 pt-6">
                  <h5 className="text-lg font-medium text-gray-900 mb-4 flex items-center gap-2">
                    <AlertCircle className="h-5 w-5 text-orange-500" />
                    Emergency Contact
                  </h5>
                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="relative group">
                      <User className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                      <input
                        type="text"
                        placeholder="Emergency Contact Name *"
                        value={formData.emergencyContactName}
                        onChange={(e) => setFormData({ ...formData, emergencyContactName: e.target.value })}
                        className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 ${
                          errors.emergencyContactName ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                        }`}
                        required
                      />
                      {errors.emergencyContactName && (
                        <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                          <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                          {errors.emergencyContactName}
                        </p>
                      )}
                    </div>
                    
                    <div className="relative group">
                      <Phone className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                      <input
                        type="tel"
                        placeholder="Emergency Contact Phone *"
                        value={formData.emergencyContactPhone}
                        onChange={(e) => setFormData({ ...formData, emergencyContactPhone: e.target.value })}
                        className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 ${
                          errors.emergencyContactPhone ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                        }`}
                        required
                      />
                      {errors.emergencyContactPhone && (
                        <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                          <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                          {errors.emergencyContactPhone}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
                
                {/* ID Verification */}
                <div className="border-t border-gray-200 pt-6">
                  <h5 className="text-lg font-medium text-gray-900 mb-4 flex items-center gap-2">
                    <UserCheck className="h-5 w-5 text-green-500" />
                    ID Verification
                  </h5>
                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="relative group">
                      <FileText className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                      <select
                        value={formData.idType}
                        onChange={(e) => setFormData({ ...formData, idType: e.target.value })}
                        className="w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 border-gray-200 appearance-none"
                      >
                        <option value="passport">Passport</option>
                        <option value="license">Driver's License</option>
                        <option value="national_id">National ID</option>
                        <option value="other">Other Government ID</option>
                      </select>
                    </div>
                    
                    <div className="relative group">
                      <UserCheck className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                      <input
                        type="text"
                        placeholder="ID Number *"
                        value={formData.idNumber}
                        onChange={(e) => setFormData({ ...formData, idNumber: e.target.value })}
                        className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 ${
                          errors.idNumber ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                        }`}
                        required
                      />
                      {errors.idNumber && (
                        <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                          <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                          {errors.idNumber}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
                
                {/* Special Requirements */}
                <div className="border-t border-gray-200 pt-6">
                  <h5 className="text-lg font-medium text-gray-900 mb-4 flex items-center gap-2">
                    <FileText className="h-5 w-5 text-blue-500" />
                    Special Requirements (Optional)
                  </h5>
                  <div className="relative group">
                    <FileText className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                    <textarea
                      placeholder="Any special requirements, accessibility needs, or additional notes..."
                      value={formData.specialRequirements}
                      onChange={(e) => setFormData({ ...formData, specialRequirements: e.target.value })}
                      rows={3}
                      className="w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 resize-none border-gray-200"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Rental Details */}
            <div className="bg-gradient-to-br from-gray-50 to-white p-6 rounded-xl border border-gray-100">
              <h4 className="text-xl font-semibold text-gray-900 mb-6 flex items-center gap-2">
                <div className="w-8 h-8 bg-accent-600 rounded-lg flex items-center justify-center">
                  <MapPin className="h-4 w-4 text-white" />
                </div>
                Rental Details
              </h4>
              
              {rentalType === 'location' && (
                <div className="space-y-6">
                  <div className="relative group">
                    <MapPin className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                    <input
                      type="text"
                      placeholder="Pickup Location"
                      value={formData.pickupLocation}
                      onChange={(e) => setFormData({ ...formData, pickupLocation: e.target.value })}
                      className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 ${
                        errors.pickupLocation ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                      }`}
                      required
                    />
                    {errors.pickupLocation && (
                      <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                        <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                        {errors.pickupLocation}
                      </p>
                    )}
                  </div>
                  <div className="relative group">
                    <MapPin className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                    <input
                      type="text"
                      placeholder="Drop-off Location"
                      value={formData.dropoffLocation}
                      onChange={(e) => setFormData({ ...formData, dropoffLocation: e.target.value })}
                      className={`w-full pl-12 pr-4 py-4 border-2 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400 ${
                        errors.dropoffLocation ? 'border-red-500 focus:border-red-500 focus:ring-red-100' : 'border-gray-200'
                      }`}
                      required
                    />
                    {errors.dropoffLocation && (
                      <p className="mt-2 text-sm text-red-600 flex items-center gap-1 animate-slide-up">
                        <div className="w-1 h-1 bg-red-500 rounded-full"></div>
                        {errors.dropoffLocation}
                      </p>
                    )}
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-3">
                      Estimated Distance (km)
                    </label>
                    <input
                      type="number"
                      min="1"
                      max="1000"
                      value={formData.distance}
                      onChange={(e) => setFormData({ ...formData, distance: parseInt(e.target.value) })}
                      className="w-full px-4 py-4 border-2 border-gray-200 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400"
                    />
                  </div>
                </div>
              )}

              {rentalType === 'hourly' && (
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-3">
                    Number of Hours
                  </label>
                  <div className="relative group">
                    <Clock className="absolute left-4 top-4 h-5 w-5 text-gray-400 transition-colors group-focus-within:text-primary-600" />
                    <input
                      type="number"
                      min="1"
                      max="24"
                      value={formData.hours}
                      onChange={(e) => setFormData({ ...formData, hours: parseInt(e.target.value) })}
                      className="w-full pl-12 pr-4 py-4 border-2 border-gray-200 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400"
                    />
                  </div>
                </div>
              )}

              {rentalType === 'daily' && (
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-3">
                    Number of Days
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="30"
                    value={formData.days}
                    onChange={(e) => setFormData({ ...formData, days: parseInt(e.target.value) })}
                    className="w-full px-4 py-4 border-2 border-gray-200 rounded-xl bg-white transition-all duration-300 focus:ring-4 focus:ring-primary-100 focus:border-primary-500 hover:border-gray-400"
                  />
                </div>
              )}
            </div>

            {/* Payment Method */}
            <div className="bg-gradient-to-br from-gray-50 to-white p-6 rounded-xl border border-gray-100">
              <h4 className="text-xl font-semibold text-gray-900 mb-6 flex items-center gap-2">
                <div className="w-8 h-8 bg-green-600 rounded-lg flex items-center justify-center">
                  <CreditCard className="h-4 w-4 text-white" />
                </div>
                Payment Method
              </h4>
              <div className="grid grid-cols-2 gap-4">
                {siteConfig.paymentMethods.map((method, index) => {
                  const Icon = method.icon === 'Banknote' ? Banknote : method.icon === 'Wallet' ? Wallet : CreditCard;
                  const isSelected = formData.paymentMethod === method.type;
                  return (
                    <button
                      key={method.type}
                      type="button"
                      onClick={() => setFormData({ ...formData, paymentMethod: method.type as PaymentMethod })}
                      className={`group relative p-6 rounded-xl border-2 transition-all duration-300 hover:scale-105 animate-slide-up overflow-hidden ${
                        isSelected
                          ? 'border-primary-500 bg-gradient-to-br from-primary-50 to-primary-100 shadow-lg scale-105'
                          : 'border-gray-200 hover:border-primary-300 hover:bg-gradient-to-br hover:from-primary-50 hover:to-white hover:shadow-md'
                      }`}
                      style={{animationDelay: `${index * 0.1}s`}}
                    >
                      {/* Background Glow */}
                      <div className={`absolute inset-0 bg-gradient-to-br from-primary-400/10 to-green-400/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300 ${
                        isSelected ? 'opacity-100' : ''
                      }`}></div>
                      
                      {/* Selection Indicator */}
                      {isSelected && (
                        <div className="absolute top-2 right-2 w-5 h-5 bg-primary-600 rounded-full flex items-center justify-center animate-scale-in">
                          <CheckCircle className="h-3 w-3 text-white" />
                        </div>
                      )}
                      
                      <div className="relative flex flex-col items-center">
                        <div className={`p-3 rounded-lg mb-3 transition-all duration-300 group-hover:scale-110 ${
                          isSelected ? 'bg-primary-600' : 'bg-gray-100 group-hover:bg-primary-100'
                        }`}>
                          <Icon className={`h-6 w-6 transition-colors duration-300 ${
                            isSelected ? 'text-white' : `${method.color} group-hover:text-primary-600`
                          }`} />
                        </div>
                        <span className={`text-sm font-semibold transition-colors duration-300 ${
                          isSelected ? 'text-primary-900' : 'text-gray-700 group-hover:text-primary-900'
                        }`}>
                          {method.label}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
              
              {/* Wallet Balance Display */}
              {formData.paymentMethod === 'wallet' && (
                <div className="mt-4 p-4 bg-purple-50 border border-purple-200 rounded-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-purple-700">Wallet Balance:</span>
                    <span className="text-lg font-bold text-purple-900">Rs.{walletBalance.toFixed(2)}</span>
                  </div>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-sm text-purple-600">Total Fare:</span>
                    <span className="text-sm font-semibold text-purple-800">Rs.{totalFare.toFixed(2)}</span>
                  </div>
                  {walletBalance >= totalFare ? (
                    <div className="mt-2 text-sm text-green-600 flex items-center gap-1">
                      <CheckCircle className="h-4 w-4" />
                      Sufficient balance available
                    </div>
                  ) : (
                    <div className="mt-2 text-sm text-red-600 flex items-center gap-1">
                      <AlertCircle className="h-4 w-4" />
                      Insufficient balance (Need Rs.{(totalFare - walletBalance).toFixed(2)} more)
                    </div>
                  )}
                </div>
              )}
              
              {/* Payment Method Error */}
              {errors.paymentMethod && (
                <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                  <p className="text-sm text-red-600 flex items-center gap-2">
                    <AlertCircle className="h-4 w-4" />
                    {errors.paymentMethod}
                  </p>
                </div>
              )}
            </div>

            {/* Terms and Conditions */}
            <div className="bg-gradient-to-br from-gray-50 to-white p-6 rounded-xl border border-gray-100">
              <div className="flex items-start gap-4">
                <div className="flex items-center h-5">
                  <input
                    id="agreeToTerms"
                    type="checkbox"
                    checked={formData.agreeToTerms}
                    onChange={(e) => setFormData({ ...formData, agreeToTerms: e.target.checked })}
                    className="w-5 h-5 text-primary-600 bg-white border-2 border-gray-300 rounded focus:ring-primary-500 focus:ring-2 transition-all duration-200"
                  />
                </div>
                <div className="flex-1">
                  <label htmlFor="agreeToTerms" className="text-sm text-gray-700 cursor-pointer">
                    <span className="font-medium">I agree to the </span>
                    <a href="#" className="text-primary-600 hover:text-primary-700 font-semibold underline transition-colors">
                      Terms and Conditions
                    </a>
                    <span className="font-medium"> and </span>
                    <a href="#" className="text-primary-600 hover:text-primary-700 font-semibold underline transition-colors">
                      Privacy Policy
                    </a>
                    <span className="font-medium">. I understand the rental policies and cancellation terms.</span>
                  </label>
                  <div className="flex items-center gap-2 mt-2">
                    <FileText className="h-4 w-4 text-gray-400" />
                    <span className="text-xs text-gray-500">Required to complete your booking</span>
                  </div>
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting || !formData.agreeToTerms}
              className="group relative w-full bg-gradient-to-r from-primary-600 to-primary-700 hover:from-primary-700 hover:to-primary-800 disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed text-white font-bold py-5 px-8 rounded-xl transition-all duration-300 hover:scale-105 hover:shadow-lg disabled:hover:scale-100 disabled:hover:shadow-none overflow-hidden"
            >
              {/* Button Glow Effect */}
              <div className="absolute inset-0 bg-gradient-to-r from-primary-400/20 to-accent-400/20 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              
              {/* Button Content */}
              <div className="relative flex items-center justify-center gap-3">
                {isSubmitting ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    <span>Processing...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="h-5 w-5 transition-transform group-hover:scale-110" />
                    <span>Confirm Booking - {siteConfig.currency.symbol}{totalFare.toLocaleString()}</span>
                  </>
                )}
              </div>
            </button>
          </form>
        </div>

        {/* Booking Summary */}
        <div className="bg-gradient-to-br from-gray-50 to-white rounded-xl p-8 border border-gray-100 animate-slide-up" style={{animationDelay: '0.2s'}}>
          <h4 className="text-2xl font-semibold text-gray-900 mb-6 flex items-center gap-2">
            <div className="w-8 h-8 bg-gradient-to-r from-primary-600 to-accent-600 rounded-lg flex items-center justify-center">
              <CheckCircle className="h-4 w-4 text-white" />
            </div>
            Booking Summary
          </h4>
          
          <div className="space-y-6">
            <div className="flex items-center gap-4 p-4 bg-white rounded-xl border border-gray-100 shadow-sm">
              <div className="relative">
                <img
                  src={vehicle.image}
                  alt={vehicle.name}
                  className="w-20 h-20 rounded-xl object-cover shadow-md"
                />
                <div className="absolute -top-1 -right-1 w-6 h-6 bg-green-500 rounded-full flex items-center justify-center">
                  <CheckCircle className="h-3 w-3 text-white" />
                </div>
              </div>
              <div className="flex-1">
                <h5 className="font-bold text-gray-900 text-lg">{vehicle.name}</h5>
                <p className="text-sm text-gray-600 mt-1">{vehicle.description}</p>
                <div className="flex items-center gap-2 mt-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-xs font-medium text-green-600">Available Now</span>
                </div>
              </div>
            </div>
            
            <div className="bg-white rounded-xl p-4 border border-gray-100 space-y-4">
              <h6 className="font-semibold text-gray-900 text-sm uppercase tracking-wide border-b border-gray-100 pb-2">Trip Details</h6>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gradient-to-br from-primary-50 to-primary-100 p-3 rounded-lg">
                  <span className="text-xs font-medium text-primary-600 uppercase tracking-wide">Rental Type</span>
                  <p className="font-bold text-primary-900 capitalize mt-1">{rentalType}</p>
                </div>
                
                <div className="bg-gradient-to-br from-accent-50 to-accent-100 p-3 rounded-lg">
                  <span className="text-xs font-medium text-accent-600 uppercase tracking-wide">From Date</span>
                  <p className="font-bold text-accent-900 mt-1">{fromDate.toLocaleDateString()}</p>
                </div>
                
                <div className="bg-gradient-to-br from-green-50 to-green-100 p-3 rounded-lg">
                  <span className="text-xs font-medium text-green-600 uppercase tracking-wide">To Date</span>
                  <p className="font-bold text-green-900 mt-1">{toDate.toLocaleDateString()}</p>
                </div>
                
                {rentalType === 'hourly' && (
                  <div className="bg-gradient-to-br from-blue-50 to-blue-100 p-3 rounded-lg">
                    <span className="text-xs font-medium text-blue-600 uppercase tracking-wide">Duration</span>
                    <p className="font-bold text-blue-900 mt-1">{formData.hours} hours</p>
                  </div>
                )}
                
                {rentalType === 'daily' && (
                  <div className="bg-gradient-to-br from-blue-50 to-blue-100 p-3 rounded-lg">
                    <span className="text-xs font-medium text-blue-600 uppercase tracking-wide">Duration</span>
                    <p className="font-bold text-blue-900 mt-1">{formData.days} days</p>
                  </div>
                )}
                
                {rentalType === 'location' && (
                  <div className="bg-gradient-to-br from-blue-50 to-blue-100 p-3 rounded-lg">
                    <span className="text-xs font-medium text-blue-600 uppercase tracking-wide">Distance</span>
                    <p className="font-bold text-blue-900 mt-1">{formData.distance} km</p>
                  </div>
                )}
              </div>
            </div>
            
            <div className="relative bg-gradient-to-r from-green-500 to-green-600 rounded-xl p-6 text-white shadow-lg overflow-hidden">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-sm font-medium opacity-90 uppercase tracking-wide">Total Fare</span>
                  <div className="flex items-center gap-2 mt-1">
                    <CheckCircle className="h-5 w-5" />
                    <span className="text-lg font-semibold">All inclusive</span>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-3xl font-bold">
                    {siteConfig.currency.symbol}{totalFare.toLocaleString()}
                  </div>
                  <div className="text-sm opacity-90 mt-1">No hidden fees</div>
                </div>
              </div>
              
              {/* Animated background effect */}
              <div className="absolute inset-0 bg-gradient-to-r from-green-400/20 to-green-600/20 rounded-xl animate-pulse"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BookingForm;