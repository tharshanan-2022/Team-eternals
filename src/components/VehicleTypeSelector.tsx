import React from 'react';
import { VehicleType } from '../types';

// Import realistic vehicle images
import realisticCar from '../assets/car.png';
import realisticBike from '../assets/black-motorcycle-white.png';
import realisticVan from '../assets/van.png';
import realisticLorry from '../assets/lorry.png';
import realisticThreewheel from '../assets/auto.png';

interface VehicleTypeSelectorProps {
  selectedType: VehicleType;
  onTypeChange: (type: VehicleType) => void;
  vehicleTypes: any[];
  loading?: boolean;
}

const getVehicleImage = (type: string) => {
  switch (type.toLowerCase()) {
    case 'bike': return realisticBike;
    case 'car': return realisticCar;
    case 'threewheel': return realisticThreewheel;
    case 'van': return realisticVan;
    case 'lorry': return realisticLorry;
    default: return realisticCar;
  }
};

const getTypeLabel = (type: string) => {
  switch (type.toLowerCase()) {
    case 'bike': return 'Bike';
    case 'car': return 'Car';
    case 'threewheel': return 'Three Wheeler';
    case 'van': return 'Van';
    case 'lorry': return 'Lorry';
    default: return type.charAt(0).toUpperCase() + type.slice(1);
  }
};

const getTypeColor = (type: string) => {
  switch (type.toLowerCase()) {
    case 'bike': return 'text-success-600';
    case 'car': return 'text-primary-600';
    case 'threewheel': return 'text-warning-600';
    case 'van': return 'text-secondary-600';
    case 'lorry': return 'text-danger-600';
    default: return 'text-gray-600';
  }
};

const getTypeGradient = (type: string) => {
  switch (type.toLowerCase()) {
    case 'bike': return 'from-success-500 to-success-600';
    case 'car': return 'from-primary-500 to-primary-600';
    case 'threewheel': return 'from-warning-500 to-warning-600';
    case 'van': return 'from-secondary-500 to-secondary-600';
    case 'lorry': return 'from-danger-500 to-danger-600';
    default: return 'from-gray-500 to-gray-600';
  }
};

const VehicleTypeSelector: React.FC<VehicleTypeSelectorProps> = ({
  selectedType,
  onTypeChange,
  vehicleTypes,
  loading = false,
}) => {
  if (loading) {
    return (
      <div className="bg-white/90 backdrop-blur-lg rounded-3xl shadow-glow p-10 mb-10 border border-primary-200/30">
        <h3 className="text-4xl font-bold bg-gradient-to-r from-primary-900 via-secondary-800 to-primary-700 bg-clip-text text-transparent mb-10 text-center">
          Choose Your Vehicle Type
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3 gap-6 lg:gap-8">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="p-6 lg:p-8 rounded-2xl border-2 border-gray-200 animate-pulse bg-gradient-to-br from-gray-50 to-gray-100 min-h-[160px] flex flex-row items-center justify-start gap-4">
              <div className="h-16 w-16 bg-gradient-to-br from-gray-300 to-gray-400 rounded-2xl flex-shrink-0 animate-shimmer"></div>
              <div className="h-5 bg-gradient-to-r from-gray-300 to-gray-400 rounded-xl flex-1 animate-shimmer"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white/90 backdrop-blur-lg rounded-3xl shadow-glow p-10 mb-10 border border-primary-200/30 animate-fade-in-up relative overflow-hidden">
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-5">
        <div className="absolute inset-0 bg-gradient-to-br from-primary-500 via-secondary-500 to-primary-600"></div>
        <div className="absolute inset-0" style={{
          backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(255,255,255,0.3) 1px, transparent 0)',
          backgroundSize: '20px 20px'
        }}></div>
      </div>
      
      <div className="relative text-center mb-10">
        <h3 className="text-4xl font-bold bg-gradient-to-r from-primary-900 via-secondary-800 to-primary-700 bg-clip-text text-transparent mb-3">
          Choose Your Vehicle Type
        </h3>
        <p className="text-gray-600 text-lg">Select the perfect vehicle for your journey</p>
        <div className="w-24 h-1 bg-gradient-to-r from-primary-500 to-secondary-500 mx-auto mt-4 rounded-full"></div>
      </div>
      
      <div className="relative grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3 gap-6 lg:gap-8">
        {vehicleTypes.map((vehicleType, index) => {
          const vehicleImage = getVehicleImage(vehicleType.type);
          const isSelected = selectedType === vehicleType.type;
          const typeGradient = getTypeGradient(vehicleType.type);
          
          return (
            <button
              key={vehicleType.type}
              onClick={() => onTypeChange(vehicleType.type as VehicleType)}
              className={`group relative p-6 lg:p-8 rounded-2xl border-2 transition-all duration-700 hover:scale-110 hover:-translate-y-2 transform animate-fade-in-up overflow-hidden min-h-[160px] flex items-center ${
                isSelected
                  ? `border-primary-400 bg-gradient-to-br from-primary-50 via-secondary-50 to-primary-100 shadow-glow scale-110 -translate-y-2`
                  : 'border-gray-200 hover:border-primary-300 hover:bg-gradient-to-br hover:from-primary-50 hover:via-white hover:to-secondary-50 hover:shadow-glow'
              }`}
              style={{animationDelay: `${index * 0.15}s`}}
            >
              {/* Background Glow Effect */}
              <div className={`absolute inset-0 bg-gradient-to-br ${typeGradient} opacity-0 group-hover:opacity-10 transition-all duration-500 ${
                isSelected ? 'opacity-15' : ''
              }`}></div>
              
              {/* Animated Border */}
              <div className={`absolute inset-0 rounded-2xl bg-gradient-to-r ${typeGradient} opacity-0 group-hover:opacity-20 transition-all duration-500 blur-sm ${
                isSelected ? 'opacity-30 animate-pulse-glow' : ''
              }`}></div>
              
              {/* Selection Indicator */}
              {isSelected && (
                <div className={`absolute top-3 right-3 w-8 h-8 bg-gradient-to-r ${typeGradient} rounded-full flex items-center justify-center animate-scale-up shadow-glow`}>
                  <div className="w-3 h-3 bg-white rounded-full animate-pulse"></div>
                </div>
              )}
              
              <div className="relative flex items-center gap-4 w-full">
                <div className={`p-4 rounded-2xl transition-all duration-500 group-hover:scale-110 flex-shrink-0 ${
                  isSelected 
                    ? `bg-gradient-to-br from-white to-gray-50 shadow-glow animate-float` 
                    : `bg-gradient-to-br from-gray-100 to-gray-200 group-hover:bg-gradient-to-br group-hover:from-white group-hover:to-gray-50`
                }`}>
                  <img 
                    src={vehicleImage}
                    alt={getTypeLabel(vehicleType.type)}
                    className="h-16 w-16 transition-all duration-500 drop-shadow-lg object-contain filter group-hover:brightness-110"
                  />
                </div>
                
                <div className="flex-1">
                  <span className={`text-base font-bold transition-all duration-500 mb-2 block ${
                    isSelected ? 'text-primary-900' : 'text-gray-700 group-hover:text-primary-900'
                  }`}>
                    {getTypeLabel(vehicleType.type)}
                  </span>
                
                  <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-semibold transition-all duration-500 ${
                    isSelected 
                      ? `bg-gradient-to-r ${typeGradient} text-white shadow-glow` 
                      : 'bg-gradient-to-r from-gray-200 to-gray-300 text-gray-600 group-hover:from-primary-200 group-hover:to-secondary-200 group-hover:text-primary-800'
                  }`}>
                    <div className={`w-2 h-2 rounded-full animate-pulse ${
                      isSelected ? 'bg-white' : 'bg-gray-400 group-hover:bg-primary-600'
                    }`}></div>
                    {vehicleType.available_vehicles} available
                  </div>
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default VehicleTypeSelector;