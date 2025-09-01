import React, { useState, useEffect } from 'react';
import { format, addDays } from 'date-fns';
import Header from './components/Header';
import Hero from './components/Hero';
import Services from './components/Services';
import Footer from './components/Footer';
import VehicleTypeSelector from './components/VehicleTypeSelector';
import DatePicker from './components/DatePicker';
import VehicleCard from './components/VehicleCard';
import RentalTypeSelector from './components/RentalTypeSelector';
import BookingForm from './components/BookingForm';
import BookingConfirmation from './components/BookingConfirmation';
import TripLookup from './components/TripLookup';
import AuthModal from './components/AuthModal';
import UserDashboard from './components/UserDashboard';
import Gamification from './components/Gamification';
import { Vehicle, VehicleType, RentalType, BookingDetails, User } from './types';
type AppStep = 'hero' | 'selection' | 'vehicles' | 'rental' | 'booking' | 'confirmation';

function App() {
  const [currentStep, setCurrentStep] = useState<AppStep>('hero');
  const [selectedVehicleType, setSelectedVehicleType] = useState<VehicleType>('car');
  const [selectedVehicle, setSelectedVehicle] = useState<Vehicle | null>(null);
  const [selectedRentalType, setSelectedRentalType] = useState<RentalType>('location');
  const [showTripLookup, setShowTripLookup] = useState(false);
  const [confirmedBooking, setConfirmedBooking] = useState<(BookingDetails & { tripId: string }) | null>(null);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [showUserDashboard, setShowUserDashboard] = useState(false);
  const [showGamification, setShowGamification] = useState(false);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [vehicles, setVehicles] = useState<Vehicle[]>([]);
  const [vehicleTypes, setVehicleTypes] = useState<any[]>([]);
  const [loadingVehicles, setLoadingVehicles] = useState(false);

  const today = new Date();
  const tomorrow = addDays(today, 1);
  
  const [fromDate, setFromDate] = useState(format(today, 'yyyy-MM-dd'));
  const [toDate, setToDate] = useState(format(tomorrow, 'yyyy-MM-dd'));

  const filteredVehicles = vehicles; // Backend already filters by type

  // Fetch vehicle types from API
  const fetchVehicleTypes = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/vehicles/types/summary');
      if (response.ok) {
        const data = await response.json();
        setVehicleTypes(data.summary);
      }
    } catch (error) {
      console.error('Failed to fetch vehicle types:', error);
    }
  };

  // Fetch vehicles from API
  const fetchVehicles = async (type?: string) => {
    try {
      setLoadingVehicles(true);
      const url = type 
        ? `http://localhost:5000/api/vehicles?type=${type}&available=true`
        : 'http://localhost:5000/api/vehicles?available=true';
      
      const response = await fetch(url);
      if (response.ok) {
        const data = await response.json();
        setVehicles(data.vehicles);
      }
    } catch (error) {
      console.error('Failed to fetch vehicles:', error);
    } finally {
      setLoadingVehicles(false);
    }
  };

  // Check for existing auth token on app load
  useEffect(() => {
    const token = localStorage.getItem('taxi_booking_token');
    if (token) {
      setAuthToken(token);
      // Verify token and get user data
      verifyToken(token);
    }
    
    // Load vehicle types and initial vehicles
    fetchVehicleTypes();
    fetchVehicles();
  }, []);

  // Fetch vehicles when vehicle type changes
  useEffect(() => {
    if (selectedVehicleType) {
      fetchVehicles(selectedVehicleType);
    }
  }, [selectedVehicleType]);

  const verifyToken = async (token: string) => {
    try {
      const response = await fetch('http://localhost:5000/api/auth/verify', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setCurrentUser(data.user);
      } else {
        // Token is invalid, remove it
        localStorage.removeItem('taxi_booking_token');
        setAuthToken(null);
      }
    } catch (error) {
      console.error('Token verification failed:', error);
      localStorage.removeItem('taxi_booking_token');
      setAuthToken(null);
    }
  };

  const handleLogin = (user: User, token: string) => {
    setCurrentUser(user);
    setAuthToken(token);
    setShowAuthModal(false);
  };

  const handleLogout = () => {
    localStorage.removeItem('taxi_booking_token');
    setCurrentUser(null);
    setAuthToken(null);
    setShowUserDashboard(false);
  };

  const handleGamification = () => {
    setShowGamification(true);
  };

  const handleGetStarted = () => {
    setCurrentStep('selection');
  };

  const handleVehicleSelect = (vehicle: Vehicle) => {
    setSelectedVehicle(vehicle);
    setCurrentStep('rental');
  };

  const handleRentalTypeNext = () => {
    setCurrentStep('booking');
  };

  const handleBookingComplete = (booking: BookingDetails & { tripId: string }) => {
    setConfirmedBooking(booking);
    setCurrentStep('confirmation');
  };

  const handleNewBooking = () => {
    setCurrentStep('hero');
    setSelectedVehicle(null);
    setConfirmedBooking(null);
  };

  const handleBackToVehicles = () => {
    setCurrentStep('vehicles');
  };

  const handleProceedToVehicles = () => {
    setCurrentStep('vehicles');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Header 
          onTripLookup={() => setShowTripLookup(true)}
          currentUser={currentUser}
          onLogin={() => setShowAuthModal(true)}
          onDashboard={() => setShowUserDashboard(true)}
          onLogout={handleLogout}
          onHome={handleNewBooking}
          onGamification={handleGamification}
        />
      
      <main className="pt-16">
        {currentStep === 'hero' && (
          <>
            <Hero 
              onGetStarted={handleGetStarted}
              selectedVehicleType={selectedVehicleType}
              onVehicleTypeChange={setSelectedVehicleType}
              fromDate={fromDate}
              toDate={toDate}
              onFromDateChange={setFromDate}
              onToDateChange={setToDate}
              vehicleTypes={vehicleTypes}
              onProceedToVehicles={handleProceedToVehicles}
            />
            <Services />
            <Footer />
          </>
        )}

        {currentStep === 'selection' && (
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold text-gray-900 mb-4">
                Book Your Perfect Vehicle
              </h2>
              <p className="text-lg text-gray-600">
                Choose your dates and vehicle type to get started
              </p>
            </div>

            <DatePicker
              fromDate={fromDate}
              toDate={toDate}
              onFromDateChange={setFromDate}
              onToDateChange={setToDate}
            />

            <VehicleTypeSelector
              selectedType={selectedVehicleType}
              onTypeChange={setSelectedVehicleType}
              vehicleTypes={vehicleTypes}
              loading={loadingVehicles}
            />

            <div className="text-center">
              <button
                onClick={handleProceedToVehicles}
                className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 px-8 rounded-full text-lg transition-all duration-300 transform hover:scale-105"
              >
                Find Available Vehicles
              </button>
            </div>
          </div>
        )}

        {currentStep === 'vehicles' && (
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <div className="flex items-center justify-between mb-8">
              <div>
                <h2 className="text-3xl font-bold text-gray-900 mb-2">
                  Available {selectedVehicleType.charAt(0).toUpperCase() + selectedVehicleType.slice(1)}s
                </h2>
                <p className="text-gray-600">
                  {format(new Date(fromDate), 'MMM dd')} - {format(new Date(toDate), 'MMM dd, yyyy')}
                </p>
              </div>
              <button
                onClick={() => setCurrentStep('selection')}
                className="text-blue-600 hover:text-blue-700 font-medium"
              >
                ← Change Dates/Type
              </button>
            </div>

            {loadingVehicles ? (
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {[1, 2, 3, 4, 5, 6].map((i) => (
                  <div key={i} className="bg-white rounded-2xl shadow-lg p-6 animate-pulse">
                    <div className="h-48 bg-gray-300 rounded-xl mb-4"></div>
                    <div className="h-6 bg-gray-300 rounded mb-2"></div>
                    <div className="h-4 bg-gray-300 rounded mb-4"></div>
                    <div className="h-10 bg-gray-300 rounded"></div>
                  </div>
                ))}
              </div>
            ) : filteredVehicles.length > 0 ? (
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredVehicles.map((vehicle) => (
                  <VehicleCard
                    key={vehicle.id}
                    vehicle={vehicle}
                    onSelect={handleVehicleSelect}
                  />
                ))}
              </div>
            ) : (
              <div className="text-center py-12">
                <div className="text-gray-500 text-lg mb-4">
                  No vehicles available for the selected type and dates.
                </div>
                <button
                  onClick={() => setCurrentStep('selection')}
                  className="text-blue-600 hover:text-blue-700 font-medium"
                >
                  Try different dates or vehicle type
                </button>
              </div>
            )}
          </div>
        )}

        {currentStep === 'rental' && selectedVehicle && (
          <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <div className="flex items-center justify-between mb-8">
              <div>
                <h2 className="text-3xl font-bold text-gray-900 mb-2">
                  Configure Your Rental
                </h2>
                <p className="text-gray-600">Selected: {selectedVehicle.name}</p>
              </div>
              <button
                onClick={() => setCurrentStep('vehicles')}
                className="text-blue-600 hover:text-blue-700 font-medium"
              >
                ← Back to Vehicles
              </button>
            </div>

            <RentalTypeSelector
              selectedType={selectedRentalType}
              onTypeChange={setSelectedRentalType}
            />

            <div className="text-center">
              <button
                onClick={handleRentalTypeNext}
                className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 px-8 rounded-full text-lg transition-all duration-300"
              >
                Proceed to Booking
              </button>
            </div>
          </div>
        )}

        {currentStep === 'booking' && selectedVehicle && (
          <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <BookingForm
              vehicle={selectedVehicle}
              rentalType={selectedRentalType}
              fromDate={new Date(fromDate)}
              toDate={new Date(toDate)}
              onBookingComplete={handleBookingComplete}
              onBack={handleBackToVehicles}
            />
          </div>
        )}

        {currentStep === 'confirmation' && confirmedBooking && selectedVehicle && (
          <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <BookingConfirmation
              booking={confirmedBooking}
              vehicle={selectedVehicle}
              onNewBooking={handleNewBooking}
            />
          </div>
        )}
      </main>

      {showTripLookup && (
        <TripLookup onClose={() => setShowTripLookup(false)} />
      )}

      {showAuthModal && (
        <AuthModal
          isOpen={showAuthModal}
          onClose={() => setShowAuthModal(false)}
          onLogin={handleLogin}
        />
      )}

      {showUserDashboard && currentUser && (
        <UserDashboard
          user={currentUser}
          onLogout={handleLogout}
          onClose={() => setShowUserDashboard(false)}
        />
      )}

      {showGamification && (
        <Gamification
          onClose={() => setShowGamification(false)}
          authToken={authToken}
        />
      )}
    </div>
  );
}

export default App;