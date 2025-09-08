import React from 'react';
import { Check, Users, Clock, Calendar, Star } from 'lucide-react';
import { Vehicle } from '../types';
import { siteConfig } from '../config/siteData';

interface VehicleCardProps {
  vehicle: Vehicle;
  onSelect: (vehicle: Vehicle) => void;
}

const getVehicleTypeColor = (type: string) => {
  switch (type.toLowerCase()) {
    case 'bike': return 'bg-gradient-to-r from-success-100 to-success-200 text-success-800 border-success-300';
    case 'threewheel': return 'bg-gradient-to-r from-warning-100 to-warning-200 text-warning-800 border-warning-300';
    case 'car': return 'bg-gradient-to-r from-primary-100 to-primary-200 text-primary-800 border-primary-300';
    case 'van': return 'bg-gradient-to-r from-secondary-100 to-secondary-200 text-secondary-800 border-secondary-300';
    case 'lorry': return 'bg-gradient-to-r from-danger-100 to-danger-200 text-danger-800 border-danger-300';
    default: return 'bg-gradient-to-r from-gray-100 to-gray-200 text-gray-800 border-gray-300';
  }
};

const getVehicleTypeLabel = (type: string) => {
  switch (type.toLowerCase()) {
    case 'bike': return 'Bike';
    case 'threewheel': return 'Three Wheeler';
    case 'car': return 'Car';
    case 'van': return 'Van';
    case 'lorry': return 'Truck/Lorry';
    default: return type.charAt(0).toUpperCase() + type.slice(1);
  }
};

const VehicleCard: React.FC<VehicleCardProps> = ({ vehicle, onSelect }) => {
  return (
    <div className="group bg-white/95 backdrop-blur-lg rounded-3xl shadow-glow overflow-hidden hover:shadow-2xl transition-all duration-700 transform hover:-translate-y-3 hover:scale-[1.03] animate-fade-in-up border border-primary-200/30 hover:border-primary-400/50 relative">
      <div className="relative aspect-w-16 aspect-h-10 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-t from-black/20 via-transparent to-transparent z-10"></div>
        <img
          src={vehicle.image}
          alt={vehicle.name}
          className="w-full h-48 object-cover group-hover:scale-110 transition-transform duration-700"
        />
        
        {/* Animated Type Badge */}
        <div className="absolute top-4 left-4 z-20">
          <span className={`px-4 py-2 rounded-2xl text-sm font-bold backdrop-blur-xl border shadow-glow ${getVehicleTypeColor(vehicle.type)} animate-fade-in-right`}>
            {getVehicleTypeLabel(vehicle.type)}
          </span>
        </div>
        
        {/* Animated Availability Badge */}
        <div className="absolute top-4 right-4 z-20">
          <div className={`px-4 py-2 rounded-2xl text-sm font-bold backdrop-blur-xl border shadow-glow animate-fade-in-left ${
            vehicle.available 
              ? 'bg-gradient-to-r from-success-500 to-success-600 text-white border-success-400' 
              : 'bg-gradient-to-r from-danger-500 to-danger-600 text-white border-danger-400'
          }`}>
            <div className="flex items-center gap-2">
              <div className={`w-2.5 h-2.5 rounded-full ${
                vehicle.available ? 'bg-success-200 animate-pulse' : 'bg-danger-200'
              }`}></div>
              {vehicle.available ? 'Available' : 'Not Available'}
            </div>
          </div>
        </div>
        
        {/* Hover Overlay */}
        <div className="absolute inset-0 bg-gradient-to-t from-primary-600/30 via-secondary-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-all duration-500 z-10"></div>
        
        {/* Animated Border Glow */}
        <div className="absolute inset-0 bg-gradient-to-r from-primary-500 via-secondary-500 to-primary-600 opacity-0 group-hover:opacity-20 transition-all duration-500 blur-sm animate-pulse-glow"></div>
      </div>
      
      <div className="p-6 relative">
        {/* Header Section */}
        <div className="flex items-start justify-between mb-6">
          <div className="flex-1">
            <h3 className="text-2xl font-bold bg-gradient-to-r from-gray-900 to-primary-800 bg-clip-text text-transparent mb-3 group-hover:from-primary-700 group-hover:to-secondary-700 transition-all duration-500">
              {vehicle.name}
            </h3>
            <div className="flex items-center gap-3 mb-3">
              <span className="text-sm text-gray-500 bg-gradient-to-r from-gray-100 to-gray-200 px-3 py-1.5 rounded-xl border border-gray-300 font-medium">ID: {vehicle.id}</span>
              <div className="flex items-center gap-2 bg-gradient-to-r from-accent-50 to-warning-50 px-3 py-1.5 rounded-xl border border-accent-200">
                <Star className="h-4 w-4 text-warning-500 fill-current" />
                <span className="text-sm font-bold text-gray-800">4.8</span>
                <span className="text-xs text-gray-600">(124 reviews)</span>
              </div>
            </div>
          </div>
          
          {/* Floating Action Indicator */}
          <div className="opacity-0 group-hover:opacity-100 transition-all duration-500 transform translate-x-3 group-hover:translate-x-0 scale-75 group-hover:scale-100">
            <div className="w-10 h-10 bg-gradient-to-r from-primary-600 to-secondary-600 rounded-2xl flex items-center justify-center shadow-glow animate-pulse-glow">
              <Check className="w-5 h-5 text-white" />
            </div>
          </div>
        </div>
        
        <p className="text-gray-600 mb-6 text-sm leading-relaxed line-clamp-2">{vehicle.description}</p>
        
        {/* Enhanced Pricing Section */}
        <div className="mb-8 p-6 bg-gradient-to-br from-primary-50 via-white to-secondary-50 rounded-2xl border border-primary-200/50 group-hover:border-primary-300/70 transition-all duration-500 shadow-soft hover:shadow-glow">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-3 h-3 bg-gradient-to-r from-primary-600 to-secondary-600 rounded-full animate-pulse"></div>
            <span className="text-base font-bold text-gray-800">Pricing Options</span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div className="text-center p-4 bg-gradient-to-br from-white to-primary-50 rounded-2xl shadow-soft border border-primary-200/30 hover:shadow-glow transition-all duration-300 hover:scale-105">
              <div className="font-bold text-primary-700 text-lg">{siteConfig.currency.symbol}{vehicle.basePrice}</div>
              <div className="text-gray-600 mt-2 font-medium">Base Price</div>
            </div>
            <div className="text-center p-4 bg-gradient-to-br from-white to-accent-50 rounded-2xl shadow-soft border border-accent-200/30 hover:shadow-glow transition-all duration-300 hover:scale-105">
               <div className="font-bold text-accent-700 text-lg">{siteConfig.currency.symbol}{vehicle.hourlyRate}</div>
               <div className="text-gray-600 mt-2 font-medium">Per Hour</div>
             </div>
             <div className="text-center p-4 bg-gradient-to-br from-white to-secondary-50 rounded-2xl shadow-soft border border-secondary-200/30 hover:shadow-glow transition-all duration-300 hover:scale-105">
               <div className="font-bold text-secondary-700 text-lg">{siteConfig.currency.symbol}{vehicle.dailyRate}</div>
               <div className="text-gray-600 mt-2 font-medium">Per Day</div>
             </div>
           </div>
         </div>
         
         {/* Enhanced Features Section */}
         <div className="mb-8">
           <div className="flex items-center gap-3 mb-4">
             <div className="w-3 h-3 bg-gradient-to-r from-accent-600 to-warning-600 rounded-full animate-pulse"></div>
             <span className="text-base font-bold text-gray-800">Features</span>
           </div>
           <div className="flex flex-wrap gap-3">
             {vehicle.features.map((feature, index) => (
               <span
                 key={index}
                 className="inline-flex items-center px-4 py-2 rounded-2xl text-sm font-semibold bg-gradient-to-r from-accent-100 via-accent-50 to-warning-100 text-accent-800 border border-accent-300/50 hover:from-accent-200 hover:to-warning-200 hover:border-accent-400 transition-all duration-300 hover:scale-105 shadow-soft hover:shadow-glow"
               >
                 {feature}
               </span>
             ))}
           </div>
         </div>
         
         {/* Enhanced Action Button */}
         <div className="space-y-4">
           <button
             onClick={() => onSelect(vehicle)}
             disabled={!vehicle.available}
             className={`w-full py-4 px-6 rounded-2xl font-bold text-base transition-all duration-500 transform hover:scale-[1.03] active:scale-[0.97] ${
              vehicle.available
                ? 'bg-gradient-to-r from-primary-600 via-primary-700 to-secondary-600 hover:from-primary-700 hover:via-secondary-600 hover:to-accent-600 text-white shadow-glow hover:shadow-glow-lg border border-primary-500/30 hover:border-secondary-400/50'
                : 'bg-gradient-to-r from-gray-200 to-gray-300 text-gray-500 cursor-not-allowed border border-gray-300'
            }`}
           >
             {vehicle.available ? 'Select Vehicle' : 'Not Available'}
           </button>
          
          {/* Conditional Rental Option Buttons */}
          {vehicle.available && (
            <div className="grid grid-cols-2 gap-3">
              <button className="py-3 px-4 text-sm font-bold text-accent-700 bg-gradient-to-r from-accent-50 to-accent-100 hover:from-accent-100 hover:to-accent-200 border border-accent-300/50 hover:border-accent-400 rounded-2xl transition-all duration-300 hover:scale-105 shadow-soft hover:shadow-glow">
                Hourly Rental
              </button>
              <button className="py-3 px-4 text-sm font-bold text-secondary-700 bg-gradient-to-r from-secondary-50 to-secondary-100 hover:from-secondary-100 hover:to-secondary-200 border border-secondary-300/50 hover:border-secondary-400 rounded-2xl transition-all duration-300 hover:scale-105 shadow-soft hover:shadow-glow">
                Daily Rental
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default VehicleCard;