export interface Vehicle {
  id: string;
  type: VehicleType;
  name: string;
  description: string;
  image: string;
  basePrice: number;
  hourlyRate: number;
  dailyRate: number;
  features: string[];
  available: boolean;
}

export type VehicleType = 'bike' | 'threewheel' | 'car' | 'van' | 'lorry';

export type RentalType = 'location' | 'hourly' | 'daily';

export type PaymentMethod = 'cash' | 'card' | 'wallet';

export interface BookingDetails {
  vehicleId: string;
  rentalType: RentalType;
  fromDate: Date;
  toDate: Date;
  pickupLocation?: string;
  dropoffLocation?: string;
  hours?: number;
  days?: number;
  totalFare: number;
  paymentMethod: PaymentMethod;
  customerName: string;
  customerEmail: string;
  customerPhone: string;
  isGuest: boolean;
}

export interface Booking {
  id: string;
  tripId: string;
  userId?: string;
  vehicle: Vehicle;
  details: BookingDetails;
  status: 'confirmed' | 'completed' | 'cancelled';
  createdAt: Date;
  updatedAt: Date;
}

export interface User {
  id: string;
  email: string;
  name: string;
  phone: string;
  createdAt: Date;
}