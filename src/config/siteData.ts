// Site Configuration and Dynamic Data for Sri Lankan Vehicle Booking App
export const siteConfig = {
  // Site Information
  siteName: "VehicleBook.lk",
  tagline: "Your Journey, Our Vehicles",
  description: "From bikes to lorries, find the perfect vehicle for your needs in Sri Lanka. Book instantly with flexible pricing options.",
  
  // Contact Information
  contact: {
    phone: "+94 11 234 5678",
    email: "info@vehiclebook.lk",
    address: "123 Galle Road, Colombo 03, Sri Lanka"
  },

  // Currency Settings
  currency: {
    code: "LKR",
    symbol: "Rs.",
    name: "Sri Lankan Rupee"
  },

  // Hero Section Content
  hero: {
    title: "Your Journey,",
    highlightText: "Our Vehicles",
    subtitle: "From bikes to lorries, find the perfect vehicle for your needs in Sri Lanka. Book instantly with flexible pricing options.",
    features: [
      {
        icon: "MapPin",
        text: "Island-wide Service"
      },
      {
        icon: "Clock", 
        text: "Hourly & Daily Rates"
      },
      {
        icon: "Calendar",
        text: "Instant Confirmation"
      }
    ],
    ctaText: "Start Booking Now"
  },

  // Vehicle Types Configuration
  vehicleTypes: [
    {
      type: "bike",
      label: "Bike",
      icon: "Bike",
      color: "text-blue-600",
      description: "Motorcycles and scooters for quick city travel"
    },
    {
      type: "threewheel",
      label: "Three Wheeler",
      icon: "Car",
      color: "text-green-600", 
      description: "Tuk-tuks for convenient local transport"
    },
    {
      type: "car",
      label: "Car",
      icon: "Car",
      color: "text-purple-600",
      description: "Comfortable cars for family and business trips"
    },
    {
      type: "van",
      label: "Van",
      icon: "Bus",
      color: "text-orange-600",
      description: "Spacious vans for group travel and events"
    },
    {
      type: "lorry",
      label: "Lorry",
      icon: "Truck", 
      color: "text-red-600",
      description: "Trucks and lorries for cargo transport"
    }
  ],

  // Rental Types Configuration
  rentalTypes: [
    {
      type: "location",
      label: "Location to Location",
      icon: "MapPin",
      description: "Point-to-point travel across Sri Lanka with distance-based pricing"
    },
    {
      type: "hourly",
      label: "Hourly Rental", 
      icon: "Clock",
      description: "Rent by the hour for flexible usage in the city"
    },
    {
      type: "daily",
      label: "Daily Rental",
      icon: "Calendar", 
      description: "Full day rental for extended trips around the island"
    }
  ],

  // Payment Methods
  paymentMethods: [
    {
      type: "cash",
      label: "Cash on Arrival",
      icon: "Banknote",
      color: "text-green-600",
      description: "Pay in cash when the vehicle arrives"
    },
    {
      type: "card", 
      label: "Card Payment",
      icon: "CreditCard",
      color: "text-blue-600",
      description: "Secure online payment with credit/debit card"
    },
    {
      type: "wallet",
      label: "Digital Wallet",
      icon: "Wallet",
      color: "text-purple-600",
      description: "Pay using your digital wallet balance"
    }
  ],

  // Popular Locations in Sri Lanka
  popularLocations: [
    "Colombo",
    "Kandy", 
    "Galle",
    "Negombo",
    "Anuradhapura",
    "Polonnaruwa",
    "Nuwara Eliya",
    "Ella",
    "Sigiriya",
    "Trincomalee",
    "Jaffna",
    "Batticaloa"
  ],

  // Booking Status Options
  bookingStatuses: [
    {
      status: "confirmed",
      label: "Confirmed",
      color: "bg-green-100 text-green-700"
    },
    {
      status: "completed", 
      label: "Completed",
      color: "bg-blue-100 text-blue-700"
    },
    {
      status: "cancelled",
      label: "Cancelled", 
      color: "bg-red-100 text-red-700"
    }
  ]
};

// Vehicle Data for Sri Lankan Market
export const vehicleData = [
  // Motorcycles and Scooters
  {
    id: "bike-1",
    type: "bike",
    name: "Honda Activa 6G",
    description: "Popular automatic scooter perfect for Colombo city rides",
    image: "/src/assets/realistic-bike.svg",
    basePrice: 1500, // LKR
    hourlyRate: 350,
    dailyRate: 2800,
    features: ["Fuel Efficient", "Automatic", "City Friendly", "Helmet Included"],
    available: true,
    specifications: {
      engine: "109.51cc",
      mileage: "60 kmpl",
      fuelType: "Petrol"
    }
  },
  {
    id: "bike-2", 
    type: "bike",
    name: "Bajaj Pulsar 150",
    description: "Sporty motorcycle ideal for long distance travel",
    image: "/src/assets/realistic-bike.svg",
    basePrice: 2200,
    hourlyRate: 500,
    dailyRate: 4000,
    features: ["Powerful Engine", "Long Distance", "Sports Design", "Digital Display"],
    available: true,
    specifications: {
      engine: "149.5cc", 
      mileage: "45 kmpl",
      fuelType: "Petrol"
    }
  },
  {
    id: "bike-3",
    type: "bike",
    name: "TVS Apache RTR 160",
    description: "High performance bike for enthusiasts",
    image: "/src/assets/realistic-bike.svg", 
    basePrice: 2500,
    hourlyRate: 550,
    dailyRate: 4500,
    features: ["Racing DNA", "ABS", "LED Headlamp", "Digital Console"],
    available: true,
    specifications: {
      engine: "159.7cc",
      mileage: "42 kmpl", 
      fuelType: "Petrol"
    }
  },

  // Three Wheelers
  {
    id: "threewheel-1",
    type: "threewheel", 
    name: "Bajaj Three Wheeler",
    description: "Standard tuk-tuk for city commuting",
    image: "/src/assets/auto.png",
    basePrice: 1200,
    hourlyRate: 300,
    dailyRate: 2400,
    features: ["3 Passengers", "City Routes", "Affordable", "Local Driver"],
    available: true,
    specifications: {
      engine: "236cc",
      passengers: "3",
      fuelType: "Petrol"
    }
  },
  {
    id: "threewheel-2",
    type: "threewheel",
    name: "Piaggio Ape",
    description: "Comfortable three wheeler with better seating",
    image: "/src/assets/auto.png",
    basePrice: 1400,
    hourlyRate: 350, 
    dailyRate: 2800,
    features: ["Comfortable Seats", "Roof Cover", "3 Passengers", "Experienced Driver"],
    available: true,
    specifications: {
      engine: "230cc",
      passengers: "3",
      fuelType: "Petrol"
    }
  },

  // Cars
  {
    id: "car-1",
    type: "car",
    name: "Suzuki Alto K10",
    description: "Compact and fuel-efficient car for city driving",
    image: "/src/assets/realistic-car.svg",
    basePrice: 3500,
    hourlyRate: 800,
    dailyRate: 6500,
    features: ["AC", "5 Seater", "Fuel Efficient", "Manual Transmission"],
    available: true,
    specifications: {
      engine: "998cc",
      passengers: "5",
      fuelType: "Petrol",
      transmission: "Manual"
    }
  },
  {
    id: "car-2",
    type: "car", 
    name: "Toyota Axio",
    description: "Comfortable sedan with hybrid technology",
    image: "/src/assets/realistic-car.svg",
    basePrice: 4500,
    hourlyRate: 1000,
    dailyRate: 8500,
    features: ["Hybrid", "AC", "5 Seater", "Automatic", "GPS Navigation"],
    available: true,
    specifications: {
      engine: "1496cc Hybrid",
      passengers: "5", 
      fuelType: "Hybrid",
      transmission: "Automatic"
    }
  },
  {
    id: "car-3",
    type: "car",
    name: "Toyota Prius",
    description: "Premium hybrid car for eco-friendly travel",
    image: "/src/assets/realistic-car.svg",
    basePrice: 5500,
    hourlyRate: 1200,
    dailyRate: 10000,
    features: ["Full Hybrid", "Premium Interior", "5 Seater", "Automatic", "Bluetooth"],
    available: true,
    specifications: {
      engine: "1797cc Hybrid",
      passengers: "5",
      fuelType: "Hybrid", 
      transmission: "CVT"
    }
  },

  // Vans
  {
    id: "van-1",
    type: "van",
    name: "Toyota Hiace",
    description: "Spacious van perfect for group travel and tours",
    image: "/src/assets/realistic-van.svg",
    basePrice: 8000,
    hourlyRate: 1800,
    dailyRate: 15000,
    features: ["14 Seater", "AC", "Luggage Space", "Professional Driver", "Tour Guide Available"],
    available: true,
    specifications: {
      engine: "2982cc",
      passengers: "14",
      fuelType: "Diesel",
      transmission: "Manual"
    }
  },
  {
    id: "van-2", 
    type: "van",
    name: "Nissan Caravan",
    description: "Comfortable van for family trips and events",
    image: "/src/assets/realistic-van.svg",
    basePrice: 7500,
    hourlyRate: 1600,
    dailyRate: 13500,
    features: ["12 Seater", "AC", "Entertainment System", "Professional Driver"],
    available: true,
    specifications: {
      engine: "2488cc",
      passengers: "12",
      fuelType: "Diesel",
      transmission: "Automatic"
    }
  },

  // Lorries and Trucks
  {
    id: "lorry-1",
    type: "lorry",
    name: "Tata Ace",
    description: "Small pickup truck for city deliveries",
    image: "/src/assets/realistic-lorry.svg",
    basePrice: 6000,
    hourlyRate: 1400,
    dailyRate: 11000,
    features: ["1 Ton Capacity", "City Permit", "Driver Included", "Loading/Unloading Help"],
    available: true,
    specifications: {
      engine: "1405cc",
      capacity: "1000 kg",
      fuelType: "Diesel",
      transmission: "Manual"
    }
  },
  {
    id: "lorry-2",
    type: "lorry", 
    name: "Isuzu Forward",
    description: "Medium truck for inter-city cargo transport",
    image: "/src/assets/realistic-lorry.svg",
    basePrice: 12000,
    hourlyRate: 2500,
    dailyRate: 20000,
    features: ["5 Ton Capacity", "Island-wide Permit", "Experienced Driver", "GPS Tracking"],
    available: true,
    specifications: {
      engine: "5193cc",
      capacity: "5000 kg", 
      fuelType: "Diesel",
      transmission: "Manual"
    }
  },
  {
    id: "lorry-3",
    type: "lorry",
    name: "Mitsubishi Canter",
    description: "Reliable truck for medium-scale transport needs",
    image: "/src/assets/realistic-lorry.svg",
    basePrice: 10000,
    hourlyRate: 2200,
    dailyRate: 18000,
    features: ["3.5 Ton Capacity", "Hydraulic Tipper", "Professional Driver", "Insurance Covered"],
    available: true,
    specifications: {
      engine: "4899cc",
      capacity: "3500 kg",
      fuelType: "Diesel", 
      transmission: "Manual"
    }
  }
];

// Pricing Configuration
export const pricingConfig = {
  // Base rates per km for location-based pricing
  ratePerKm: {
    bike: 25,      // LKR per km
    threewheel: 35,      // LKR per km  
    car: 45,       // LKR per km
    van: 65,       // LKR per km
    lorry: 85      // LKR per km
  },
  
  // Minimum charges
  minimumCharges: {
    bike: 500,     // LKR
    threewheel: 400,     // LKR
    car: 1000,     // LKR  
    van: 2000,     // LKR
    lorry: 1500    // LKR
  },

  // Additional charges
  additionalCharges: {
    driverAllowance: 1500,    // LKR per day for outstation
    fuelSurcharge: 0.1,       // 10% of base fare
    nightCharges: 0.2,        // 20% extra for night trips (10 PM - 6 AM)
    waitingCharges: 150       // LKR per hour
  }
};