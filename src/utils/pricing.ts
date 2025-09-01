import { RentalType, Vehicle } from '../types';
import { pricingConfig } from '../config/siteData';

export const calculateFare = (
  vehicle: Vehicle,
  rentalType: RentalType,
  duration: number,
  distance?: number
): number => {
  let baseFare = 0;

  switch (rentalType) {
    case 'hourly':
      baseFare = vehicle.hourlyRate * duration;
      break;
    case 'daily':
      baseFare = vehicle.dailyRate * duration;
      break;
    case 'location':
      // Distance-based pricing: base price + (distance * rate per km)
      const vehicleType = vehicle.type;
      const ratePerKm = pricingConfig.ratePerKm[vehicleType] || 50;
      const minimumCharge = pricingConfig.minimumCharges[vehicleType] || 1000;
      const calculatedFare = vehicle.basePrice + (distance || 0) * ratePerKm;
      baseFare = Math.max(calculatedFare, minimumCharge);
      break;
    default:
      baseFare = vehicle.basePrice;
  }

  return Math.round(baseFare);
};

export const generateTripId = (): string => {
  return 'TRIP' + Date.now().toString().slice(-6) + Math.random().toString(36).substr(2, 4).toUpperCase();
};