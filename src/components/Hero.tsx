import React, { useEffect, useState } from 'react';
import { MapPin, Calendar, Clock, Truck, Sparkles, ArrowRight, Zap, Star, Globe, ChevronLeft, ChevronRight } from 'lucide-react';
import { siteConfig } from '../config/siteData';
import { VehicleType } from '../types';
import DatePicker from './DatePicker';
import VehicleTypeSelector from './VehicleTypeSelector';
import heroIllustration from '../assets/hero-illustration.svg';
import floatingElements from '../assets/floating-elements.svg';
import carImage from '../assets/car.png';
import bikeImage from '../assets/black-motorcycle-white.png';
import vanImage from '../assets/van.png';
import lorryImage from '../assets/lorry.png';
import threewheelImage from '../assets/auto.png';

interface HeroProps {
  onGetStarted: () => void;
  selectedVehicleType: VehicleType;
  onVehicleTypeChange: (type: VehicleType) => void;
  fromDate: string;
  toDate: string;
  onFromDateChange: (date: string) => void;
  onToDateChange: (date: string) => void;
  vehicleTypes: VehicleType[];
  onProceedToVehicles: () => void;
}

const Hero: React.FC<HeroProps> = ({
  onGetStarted,
  selectedVehicleType,
  onVehicleTypeChange,
  fromDate,
  toDate,
  onFromDateChange,
  onToDateChange,
  vehicleTypes,
  onProceedToVehicles
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [currentSlide, setCurrentSlide] = useState(0);

  const slides = [
    {
      title: "Premium Car Rentals",
      subtitle: "Experience luxury and comfort with our premium car collection",
      image: carImage,
      gradient: "from-blue-600 to-purple-700",
      accent: "from-blue-400 to-purple-500"
    },
    {
      title: "Swift Bike Rides",
      subtitle: "Navigate through traffic with our eco-friendly bike options",
      image: bikeImage,
      gradient: "from-green-600 to-teal-700",
      accent: "from-green-400 to-teal-500"
    },
    {
      title: "Spacious Vans",
      subtitle: "Perfect for group travel and cargo transportation",
      image: vanImage,
      gradient: "from-orange-600 to-red-700",
      accent: "from-orange-400 to-red-500"
    },
    {
      title: "Heavy Duty Lorries",
      subtitle: "Industrial strength vehicles for your heavy cargo needs",
      image: lorryImage,
      gradient: "from-gray-600 to-slate-700",
      accent: "from-gray-400 to-slate-500"
    },
    {
      title: "Three Wheeler Fun",
      subtitle: "Unique and affordable transportation for short distances",
      image: threewheelImage,
      gradient: "from-yellow-600 to-orange-700",
      accent: "from-yellow-400 to-orange-500"
    }
  ];

  const nextSlide = () => {
    setCurrentSlide((prev) => (prev + 1) % slides.length);
  };

  const prevSlide = () => {
    setCurrentSlide((prev) => (prev - 1 + slides.length) % slides.length);
  };

  useEffect(() => {
    setIsVisible(true);
    
    const handleMouseMove = (e: MouseEvent) => {
      setMousePosition({
        x: (e.clientX / window.innerWidth - 0.5) * 20,
        y: (e.clientY / window.innerHeight - 0.5) * 20
      });
    };

    const slideInterval = setInterval(() => {
      nextSlide();
    }, 5000);
    
    window.addEventListener('mousemove', handleMouseMove);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      clearInterval(slideInterval);
    };
  }, [slides.length]);

  return (
    <div className="relative">
      {/* Hero Slideshow Banner */}
      <div className={`relative h-screen overflow-hidden bg-gradient-to-br ${slides[currentSlide].gradient}`}>
        {/* Dynamic Background */}
        <div className="absolute inset-0">
          <div 
            className={`absolute inset-0 bg-gradient-to-r ${slides[currentSlide].accent}/10 animate-gradient-xy`}
            style={{
              transform: `translate(${mousePosition.x * 0.02}px, ${mousePosition.y * 0.02}px)`
            }}
          ></div>
          
          {/* Floating Geometric Shapes */}
          <div className={`absolute top-20 left-10 w-96 h-96 bg-gradient-to-r ${slides[currentSlide].accent}/20 rounded-full blur-3xl animate-float`}></div>
          <div className={`absolute bottom-20 right-10 w-80 h-80 bg-gradient-to-r ${slides[currentSlide].accent}/15 rounded-full blur-3xl animate-float-delayed`}></div>
          
          {/* Grid Pattern */}
          <div className="absolute inset-0 opacity-5">
            <div className="w-full h-full" style={{
              backgroundImage: 'radial-gradient(circle at 1px 1px, rgba(255,255,255,0.3) 1px, transparent 0)',
              backgroundSize: '50px 50px'
            }}></div>
          </div>
        </div>

        {/* Slide Content */}
        <div className="relative h-full flex items-center">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full">
            <div className="grid lg:grid-cols-2 gap-12 items-center">
              {/* Left Content */}
              <div className={`text-left transition-all duration-1000 ${isVisible ? 'animate-fade-in-up' : 'opacity-0 translate-y-10'}`}>
                 {/* Badge */}
                 <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-md rounded-full px-4 py-2 mb-6 border border-white/20">
                   <Zap className="h-4 w-4 text-white" />
                   <span className="text-sm font-medium text-white/90">Premium Transport Service</span>
                 </div>
                 
                 {/* Dynamic Title */}
                 <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-6 leading-tight">
                   <span className="bg-gradient-to-r from-white to-white/80 bg-clip-text text-transparent">
                     {slides[currentSlide].title}
                   </span>
                 </h1>
                 
                 {/* Dynamic Subtitle */}
                 <p className="text-xl md:text-2xl text-white/80 mb-8 leading-relaxed">
                   {slides[currentSlide].subtitle}
                 </p>
                 
                 {/* Feature Pills */}
                 <div className="flex flex-wrap gap-3 mb-8">
                   <div className="bg-white/10 backdrop-blur-md rounded-full px-4 py-2 border border-white/20">
                     <span className="text-sm font-medium text-white/90">24/7 Available</span>
                   </div>
                   <div className="bg-white/10 backdrop-blur-md rounded-full px-4 py-2 border border-white/20">
                     <span className="text-sm font-medium text-white/90">GPS Tracking</span>
                   </div>
                   <div className="bg-white/10 backdrop-blur-md rounded-full px-4 py-2 border border-white/20">
                     <span className="text-sm font-medium text-white/90">Safe & Secure</span>
                   </div>
                 </div>
            
                 {/* CTA Button */}
                 <button 
                   onClick={() => {
                     const vehicleSection = document.getElementById('choose-vehicle');
                     if (vehicleSection) {
                       vehicleSection.scrollIntoView({ behavior: 'smooth' });
                     }
                   }}
                   className="group bg-white/20 backdrop-blur-md hover:bg-white/30 text-white font-semibold py-4 px-8 rounded-2xl text-lg transition-all duration-300 transform hover:scale-105 border border-white/30 hover:border-white/50"
                 >
                   <span className="flex items-center justify-center gap-3">
                     <Globe className="h-5 w-5 group-hover:rotate-12 transition-transform" />
                     Book Now
                   </span>
                 </button>
               </div>
               
               {/* Right Content - Vehicle Image */}
               <div className="relative">
                 <div className="relative z-10">
                   <img 
                     src={slides[currentSlide].image} 
                     alt={slides[currentSlide].title}
                     className="w-full h-auto max-w-lg mx-auto transform hover:scale-105 transition-transform duration-500"
                   />
                 </div>
                 
                 {/* Decorative Elements */}
                 <div className={`absolute -top-10 -right-10 w-32 h-32 bg-gradient-to-r ${slides[currentSlide].accent}/30 rounded-full blur-2xl animate-pulse-glow`}></div>
                 <div className={`absolute -bottom-10 -left-10 w-40 h-40 bg-gradient-to-r ${slides[currentSlide].accent}/20 rounded-full blur-3xl animate-float-delayed`}></div>
               </div>
             </div>
           </div>
         </div>

         {/* Slide Navigation */}
         <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 flex items-center gap-4">
           <button 
             onClick={prevSlide}
             className="p-3 bg-white/10 backdrop-blur-md rounded-full border border-white/20 hover:bg-white/20 transition-all duration-300 text-white"
           >
             <ChevronLeft className="h-5 w-5" />
           </button>
           
           <div className="flex gap-2">
             {slides.map((_, index) => (
               <button
                 key={index}
                 onClick={() => setCurrentSlide(index)}
                 className={`w-3 h-3 rounded-full transition-all duration-300 ${
                   index === currentSlide 
                     ? 'bg-white scale-125 shadow-glow' 
                     : 'bg-white/30 hover:bg-white/50'
                 }`}
               />
             ))}
           </div>
           
           <button 
             onClick={nextSlide}
             className="p-3 bg-white/10 backdrop-blur-md rounded-full border border-white/20 hover:bg-white/20 transition-all duration-300 text-white"
           >
             <ChevronRight className="h-5 w-5" />
           </button>
         </div>

         {/* Floating Particles */}
         <div className="absolute inset-0 overflow-hidden pointer-events-none">
           {[...Array(15)].map((_, i) => (
             <div
               key={i}
               className="absolute w-1 h-1 bg-white/30 rounded-full animate-float"
               style={{
                 left: `${Math.random() * 100}%`,
                 top: `${Math.random() * 100}%`,
                 animationDelay: `${Math.random() * 5}s`,
                 animationDuration: `${4 + Math.random() * 3}s`
               }}
             />
           ))}
         </div>
       </div>

       {/* Booking Section */}
       <div className="bg-gray-50 py-16">
         <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 xl:px-12 2xl:px-16">
           <div className="bg-white/95 backdrop-blur-sm rounded-3xl shadow-2xl p-12 md:p-20 lg:p-24 xl:p-28 border border-gray-100">
             <div className="text-center mb-10">
               <h2 className="text-4xl font-bold text-gray-900 mb-4">
                 Book Your Perfect Vehicle
               </h2>
               <p className="text-xl text-gray-600">
                 Select your dates and choose your preferred vehicle type
               </p>
             </div>
             
             {/* Date Selection */}
             <div className="mb-8">
               <h3 className="text-2xl font-semibold text-gray-900 mb-6 text-center">
                 Select Your Dates
               </h3>
               <div className="grid md:grid-cols-2 gap-6">
                 <div className="relative">
                   <label className="block text-sm font-medium text-gray-700 mb-2">
                     From Date
                   </label>
                   <div className="relative">
                     <input
                       type="date"
                       value={fromDate}
                       min={new Date().toISOString().split('T')[0]}
                       onChange={(e) => onFromDateChange(e.target.value)}
                       className="w-full px-4 py-4 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 text-gray-900 pl-12 text-lg"
                     />
                     <Calendar className="absolute left-3 top-4 h-6 w-6 text-gray-400" />
                   </div>
                 </div>
                 
                 <div className="relative">
                   <label className="block text-sm font-medium text-gray-700 mb-2">
                     To Date
                   </label>
                   <div className="relative">
                     <input
                       type="date"
                       value={toDate}
                       min={fromDate || new Date().toISOString().split('T')[0]}
                       onChange={(e) => onToDateChange(e.target.value)}
                       className="w-full px-4 py-4 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 text-gray-900 pl-12 text-lg"
                     />
                     <Calendar className="absolute left-3 top-4 h-6 w-6 text-gray-400" />
                   </div>
                 </div>
               </div>
             </div>
             
             {/* Vehicle Type Selection */}
             <div id="choose-vehicle" className="mb-8">
               <h3 className="text-2xl font-semibold text-gray-900 mb-6 text-center">
                 Choose Your Vehicle
               </h3>
               <VehicleTypeSelector
                 selectedType={selectedVehicleType}
                 onTypeChange={onVehicleTypeChange}
                 vehicleTypes={vehicleTypes}
               />
             </div>
             
             {/* Find Vehicles Button */}
             <div className="text-center">
               <button
                 onClick={onProceedToVehicles}
                 disabled={!fromDate || !toDate || !selectedVehicleType}
                 className="group bg-gradient-to-r from-primary-600 to-primary-700 hover:from-primary-700 hover:to-primary-800 text-white px-12 py-4 rounded-2xl font-semibold text-xl shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none mx-auto"
               >
                 <Sparkles className="h-6 w-6 group-hover:rotate-12 transition-transform" />
                 Find Available Vehicles
                 <ArrowRight className="h-6 w-6 group-hover:translate-x-1 transition-transform" />
               </button>
             </div>
           </div>
         </div>
       </div>
    </div>
  );
};

export default Hero;