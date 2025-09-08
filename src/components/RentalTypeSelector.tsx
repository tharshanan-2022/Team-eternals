import React from 'react';
import { MapPin, Clock, Calendar } from 'lucide-react';
import { RentalType } from '../types';
import { siteConfig } from '../config/siteData';

interface RentalTypeSelectorProps {
  selectedType: RentalType;
  onTypeChange: (type: RentalType) => void;
}

const getIconComponent = (iconName: string) => {
  switch (iconName) {
    case 'MapPin': return MapPin;
    case 'Clock': return Clock;
    case 'Calendar': return Calendar;
    default: return MapPin;
  }
};

const RentalTypeSelector: React.FC<RentalTypeSelectorProps> = ({
  selectedType,
  onTypeChange,
}) => {
  return (
    <div className="bg-white rounded-2xl shadow-lg p-6 mb-8">
      <h3 className="text-2xl font-bold text-gray-900 mb-6 text-center">
        Choose Rental Type
      </h3>
      <div className="grid md:grid-cols-3 gap-4">
        {siteConfig.rentalTypes.map(({ type, label, icon, description }) => {
          const Icon = getIconComponent(icon);
          return (
          <button
            key={type}
            onClick={() => onTypeChange(type as RentalType)}
            className={`p-6 rounded-xl border-2 transition-all duration-300 text-left hover:shadow-md ${
              selectedType === type
                ? 'border-blue-500 bg-blue-50 shadow-md'
                : 'border-gray-200 hover:border-gray-300'
            }`}
          >
            <Icon className="h-8 w-8 text-blue-600 mb-3" />
            <h4 className="font-semibold text-gray-900 mb-2">{label}</h4>
            <p className="text-sm text-gray-600">{description}</p>
          </button>
          );
        })}
      </div>
    </div>
  );
};

export default RentalTypeSelector;