import React, { useState, useEffect } from 'react';
import { Car, Search, User, LogIn, Settings, Menu, X, Bell, Trophy } from 'lucide-react';
import { siteConfig } from '../config/siteData';
import { User as UserType } from '../types';

interface HeaderProps {
  onTripLookup: () => void;
  currentUser: UserType | null;
  onLogin: () => void;
  onDashboard: () => void;
  onLogout: () => void;
  onHome: () => void;
  onGamification?: () => void;
}

const Header: React.FC<HeaderProps> = ({ onTripLookup, currentUser, onLogin, onDashboard, onLogout, onHome, onGamification }) => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 10);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <header className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${
      isScrolled 
        ? 'bg-white/95 backdrop-blur-xl shadow-glow border-b border-primary-200/30' 
        : 'bg-white/90 backdrop-blur-lg shadow-soft border-b border-primary-100/20'
    }`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div 
            className="flex items-center gap-3 cursor-pointer group" 
            onClick={onHome}
          >
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-br from-primary-500 to-secondary-500 rounded-2xl blur-md opacity-0 group-hover:opacity-40 transition-all duration-500 animate-pulse-glow"></div>
              <div className="relative bg-gradient-to-br from-primary-600 via-primary-700 to-secondary-600 rounded-2xl p-3 group-hover:scale-110 group-hover:rotate-3 transition-all duration-500 shadow-glow">
                <Car className="h-6 w-6 text-white drop-shadow-lg" />
              </div>
            </div>
            <h1 className="text-xl font-bold bg-gradient-to-r from-gray-900 via-primary-800 to-secondary-800 bg-clip-text text-transparent group-hover:from-primary-600 group-hover:via-secondary-600 group-hover:to-primary-700 transition-all duration-500">
              {siteConfig.siteName}
            </h1>
          </div>
          
          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center gap-4">
            <button
              onClick={onTripLookup}
              className="group flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-primary-600 via-primary-700 to-secondary-600 text-white rounded-2xl hover:from-primary-700 hover:via-secondary-700 hover:to-primary-800 transition-all duration-500 transform hover:scale-105 hover:-translate-y-0.5 shadow-glow hover:shadow-primary-glow-lg"
            >
              <Search className="w-4 h-4 group-hover:rotate-12 group-hover:scale-110 transition-all duration-500" />
              <span className="font-semibold">Track Trip</span>
            </button>
            
            {currentUser ? (
              <div className="flex items-center gap-3">
                {/* Gamification Button */}
                {onGamification && (
                  <button
                    onClick={onGamification}
                    className="group flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-warning-500 via-warning-600 to-success-500 text-white rounded-xl hover:from-warning-600 hover:via-success-600 hover:to-warning-700 transition-all duration-500 transform hover:scale-105 hover:-translate-y-0.5 shadow-warning-glow hover:shadow-warning-glow-lg"
                  >
                    <Trophy className="w-4 h-4 group-hover:rotate-12 group-hover:scale-110 transition-all duration-500" />
                    <span className="font-semibold">Games</span>
                  </button>
                )}
                
                {/* Notification Bell */}
                <button className="relative p-3 text-gray-600 hover:text-primary-600 transition-all duration-500 hover:scale-110 hover:bg-primary-50 rounded-xl">
                  <Bell className="w-5 h-5" />
                  <span className="absolute -top-1 -right-1 w-3 h-3 bg-gradient-to-r from-danger-500 to-warning-500 rounded-full animate-pulse shadow-danger-glow"></span>
                </button>
                
                {/* User Info */}
                <div className="text-right animate-slide-left">
                  <p className="text-sm font-medium text-gray-900">{currentUser.name}</p>
                  <p className="text-xs text-gray-600">{currentUser.email}</p>
                </div>
                
                {/* User Actions */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={onDashboard}
                    className="group flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-gray-100 to-gray-200 text-gray-700 rounded-xl hover:from-primary-50 hover:to-secondary-50 hover:text-primary-700 transition-all duration-500 hover:scale-105 hover:-translate-y-0.5 shadow-soft hover:shadow-glow"
                  >
                    <Settings className="w-4 h-4 group-hover:rotate-90 group-hover:scale-110 transition-all duration-500" />
                    <span className="font-semibold">Dashboard</span>
                  </button>
                  <button
                    onClick={onLogout}
                    className="px-4 py-2.5 text-gray-600 hover:text-danger-600 hover:bg-danger-50 rounded-xl transition-all duration-500 font-semibold hover:scale-105"
                  >
                    Logout
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={onLogin}
                className="group flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-accent-400 via-accent-500 to-secondary-400 text-gray-900 rounded-2xl hover:from-accent-500 hover:via-secondary-500 hover:to-accent-600 transition-all duration-500 transform hover:scale-105 hover:-translate-y-0.5 shadow-accent-glow hover:shadow-accent-glow-lg font-semibold"
              >
                <LogIn className="w-4 h-4 group-hover:rotate-12 group-hover:scale-110 transition-all duration-500" />
                <span>Login</span>
              </button>
            )}
            
            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="md:hidden p-3 text-gray-600 hover:text-primary-600 hover:bg-primary-50 rounded-xl transition-all duration-500 hover:scale-110"
            >
              {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
        
        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="md:hidden bg-white/95 backdrop-blur-xl border-t border-primary-200/30 animate-fade-in-down shadow-glow">
            <div className="px-4 py-6 space-y-4">
              <button
                onClick={() => {
                  onTripLookup();
                  setIsMobileMenuOpen(false);
                }}
                className="w-full flex items-center gap-3 px-5 py-4 bg-gradient-to-r from-primary-600 via-primary-700 to-secondary-600 text-white rounded-2xl transition-all duration-500 shadow-glow hover:shadow-primary-glow-lg transform hover:scale-105"
              >
                <Search className="w-5 h-5" />
                <span className="font-semibold">Track Trip</span>
              </button>
              
              {currentUser ? (
                <div className="space-y-3">
                  <div className="px-5 py-4 bg-gradient-to-r from-gray-50 to-primary-50 rounded-2xl border border-primary-100">
                    <p className="text-sm font-semibold text-gray-900">{currentUser.name}</p>
                    <p className="text-xs text-gray-600">{currentUser.email}</p>
                  </div>
                  <button
                    onClick={() => {
                      onDashboard();
                      setIsMobileMenuOpen(false);
                    }}
                    className="w-full flex items-center gap-3 px-5 py-4 bg-gradient-to-r from-gray-100 to-gray-200 text-gray-700 rounded-2xl transition-all duration-500 hover:from-primary-50 hover:to-secondary-50 hover:text-primary-700 shadow-soft"
                  >
                    <Settings className="w-5 h-5" />
                    <span className="font-semibold">Dashboard</span>
                  </button>
                  <button
                    onClick={() => {
                      onLogout();
                      setIsMobileMenuOpen(false);
                    }}
                    className="w-full px-5 py-4 text-danger-600 font-semibold transition-all duration-500 hover:bg-danger-50 rounded-2xl"
                  >
                    Logout
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => {
                    onLogin();
                    setIsMobileMenuOpen(false);
                  }}
                  className="w-full flex items-center gap-3 px-5 py-4 bg-gradient-to-r from-accent-400 via-accent-500 to-secondary-400 text-gray-900 rounded-2xl transition-all duration-500 font-semibold shadow-accent-glow hover:shadow-accent-glow-lg transform hover:scale-105"
                >
                  <LogIn className="w-5 h-5" />
                  <span>Login</span>
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </header>
  );
};

export default Header;