import React from 'react';
import { Clock, Shield, MapPin, Star, Zap, Users, Calendar, Headphones } from 'lucide-react';
import carImage from '../assets/car.svg';
import bikeImage from '../assets/bike.svg';
import vanImage from '../assets/van.svg';
import lorryImage from '../assets/lorry.svg';

const Services: React.FC = () => {
  const services = [
    {
      icon: Clock,
      title: '24/7 Availability',
      description: 'Round-the-clock service for all your transportation needs',
      color: 'from-blue-500 to-blue-600'
    },
    {
      icon: Shield,
      title: 'Safe & Secure',
      description: 'Verified drivers and GPS tracking for your safety',
      color: 'from-green-500 to-green-600'
    },
    {
      icon: Zap,
      title: 'Instant Booking',
      description: 'Book your ride in seconds with our smart app',
      color: 'from-yellow-500 to-yellow-600'
    },
    {
      icon: Star,
      title: 'Premium Quality',
      description: 'Well-maintained vehicles and professional drivers',
      color: 'from-purple-500 to-purple-600'
    }
  ];

  const vehicles = [
    {
      name: 'Economy Cars',
      image: carImage,
      description: 'Perfect for daily commutes and city travel',
      features: ['AC', 'GPS', 'Music System'],
      price: 'From $15/hour',
      color: 'from-blue-500 to-blue-600'
    },
    {
      name: 'Motorcycles',
      image: bikeImage,
      description: 'Quick and efficient for short distances',
      features: ['Helmet Included', 'Fast Delivery', 'Eco-Friendly'],
      price: 'From $8/hour',
      color: 'from-red-500 to-red-600'
    },
    {
      name: 'Vans & SUVs',
      image: vanImage,
      description: 'Spacious vehicles for groups and families',
      features: ['7-8 Seater', 'Luggage Space', 'Premium Comfort'],
      price: 'From $25/hour',
      color: 'from-green-500 to-green-600'
    },
    {
      name: 'Cargo Trucks',
      image: lorryImage,
      description: 'Heavy-duty vehicles for moving and logistics',
      features: ['Large Capacity', 'Professional Driver', 'Loading Assistance'],
      price: 'From $40/hour',
      color: 'from-purple-500 to-purple-600'
    }
  ];

  const features = [
    {
      icon: Users,
      title: '10K+ Happy Customers',
      description: 'Trusted by thousands of satisfied users'
    },
    {
      icon: MapPin,
      title: '50+ Cities Covered',
      description: 'Expanding our service across major cities'
    },
    {
      icon: Calendar,
      title: 'Flexible Booking',
      description: 'Book now or schedule for later'
    },
    {
      icon: Headphones,
      title: '24/7 Support',
      description: 'Always here to help you'
    }
  ];

  return (
    <div className="bg-gradient-to-br from-gray-50 via-white to-primary-50 py-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Services Section */}
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold bg-gradient-to-r from-primary-800 to-secondary-700 bg-clip-text text-transparent mb-6">
            Why Choose Our Service?
          </h2>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Experience the best in transportation with our premium services and commitment to excellence
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8 mb-20">
          {services.map((service, index) => {
            const IconComponent = service.icon;
            return (
              <div
                key={index}
                className="group bg-white rounded-3xl p-8 shadow-soft hover:shadow-glow transition-all duration-500 hover:scale-105 border border-gray-200/50"
              >
                <div className={`w-16 h-16 bg-gradient-to-r ${service.color} rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300`}>
                  <IconComponent className="h-8 w-8 text-white" />
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-3">{service.title}</h3>
                <p className="text-gray-600 leading-relaxed">{service.description}</p>
              </div>
            );
          })}
        </div>

        {/* Vehicle Fleet Section */}
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold bg-gradient-to-r from-secondary-800 to-accent-700 bg-clip-text text-transparent mb-6">
            Our Vehicle Fleet
          </h2>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto">
            Choose from our diverse range of vehicles to suit every need and budget
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8 mb-20">
          {vehicles.map((vehicle, index) => (
            <div
              key={index}
              className="group bg-white rounded-3xl overflow-hidden shadow-soft hover:shadow-glow transition-all duration-500 hover:scale-105 border border-gray-200/50"
            >
              <div className="p-6 pb-4">
                <div className="h-32 flex items-center justify-center mb-6 bg-gradient-to-br from-gray-50 to-gray-100 rounded-2xl">
                  <img 
                    src={vehicle.image} 
                    alt={vehicle.name}
                    className="w-full h-full object-contain group-hover:scale-110 transition-transform duration-500"
                  />
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">{vehicle.name}</h3>
                <p className="text-gray-600 text-sm mb-4">{vehicle.description}</p>
                
                <div className="space-y-2 mb-4">
                  {vehicle.features.map((feature, featureIndex) => (
                    <div key={featureIndex} className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 bg-green-500 rounded-full"></div>
                      <span className="text-sm text-gray-600">{feature}</span>
                    </div>
                  ))}
                </div>
                
                <div className="flex items-center justify-between">
                  <span className={`text-lg font-bold bg-gradient-to-r ${vehicle.color} bg-clip-text text-transparent`}>
                    {vehicle.price}
                  </span>
                  <button className={`bg-gradient-to-r ${vehicle.color} text-white px-4 py-2 rounded-xl text-sm font-semibold hover:scale-105 transition-transform duration-300`}>
                    Book Now
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Features Grid */}
        <div className="bg-gradient-to-br from-primary-900 via-secondary-900 to-accent-900 rounded-3xl p-12 text-white">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Trusted by Thousands
            </h2>
            <p className="text-white/80 text-lg">
              Join our growing community of satisfied customers
            </p>
          </div>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => {
              const IconComponent = feature.icon;
              return (
                <div key={index} className="text-center group">
                  <div className="w-16 h-16 bg-white/10 backdrop-blur-md rounded-2xl flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform duration-300">
                    <IconComponent className="h-8 w-8 text-accent-400" />
                  </div>
                  <h3 className="text-xl font-bold mb-2">{feature.title}</h3>
                  <p className="text-white/70">{feature.description}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Services;