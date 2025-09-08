import React, { useState } from 'react';
import { X } from 'lucide-react';
import { User as UserType } from '../types';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLogin: (user: UserType, token: string) => void;
}

interface ResetForm {
  email: string;
  password: string;
  confirmPassword: string;
}

interface OtpForm {
  email: string;
  otp: string;
}

interface LoginForm {
  email: string;
  password: string;
}

interface RegisterForm {
  name: string;
  email: string;
  phone: string;
  password: string;
  confirmPassword: string;
}

const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onLogin }) => {
  type Mode = 'login' | 'register' | 'forgotPassword' | 'verifyOtp' | 'resetPassword';

  const [mode, setMode] = useState<Mode>('login');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [forgotForm, setForgotForm] = useState({ email: '' });
  const [otpForm, setOtpForm] = useState<OtpForm>({ email: '', otp: '' });
  const [resetForm, setResetForm] = useState<ResetForm>({ email: '', password: '', confirmPassword: '' });
  const [loginForm, setLoginForm] = useState<LoginForm>({ email: '', password: '' });
  const [registerForm, setRegisterForm] = useState<RegisterForm>({
    name: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: ''
  });

  const API_BASE_URL = 'http://localhost:5000/api';

  const resetForms = () => {
    setLoginForm({ email: '', password: '' });
    setRegisterForm({ name: '', email: '', phone: '', password: '', confirmPassword: '' });
    setForgotForm({ email: '' });
    setOtpForm({ email: '', otp: '' });
    setResetForm({ email: '', password: '', confirmPassword: '' });
    setError(null);
    setShowPassword(false);
    setShowConfirmPassword(false);
  };

  const handleClose = () => {
    resetForms();
    onClose();
  };

  const switchMode = () => {
    setMode(mode === 'login' ? 'register' : 'login');
    setError(null);
  };

  // ======= Handlers =======
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginForm)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Login failed');

      localStorage.setItem('taxi_booking_token', data.token);
      onLogin(data.user, data.token);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    if (registerForm.password !== registerForm.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(registerForm)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Registration failed');

      localStorage.setItem('taxi_booking_token', data.token);
      onLogin(data.user, data.token);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE_URL}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: forgotForm.email })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to send OTP');

      setOtpForm({ email: forgotForm.email, otp: '' });
      setMode('verifyOtp');
      alert(`OTP sent to ${forgotForm.email}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE_URL}/auth/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: otpForm.email, otp: otpForm.otp })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'OTP verification failed');

      setResetForm({ email: otpForm.email, password: '', confirmPassword: '' });
      setMode('resetPassword');
      alert(`OTP verified for ${otpForm.email}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    if (resetForm.password !== resetForm.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE_URL}/auth/reset-password`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: resetForm.email,
          password: resetForm.password,
          confirmPassword: resetForm.confirmPassword
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Password reset failed');

      setMode('login');
      alert(`Password reset successful for ${resetForm.email}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-md">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <h2 className="text-2xl font-bold text-gray-900">
            {mode === 'login'
              ? 'Welcome Back'
              : mode === 'register'
                ? 'Create Account'
                : mode === 'forgotPassword'
                  ? 'Forgot Password'
                  : mode === 'verifyOtp'
                    ? 'Verify OTP'
                    : 'Reset Password'}
          </h2>
          <button onClick={handleClose} className="p-2 hover:bg-gray-100 rounded-lg">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6">
          {error && <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded-lg">{error}</div>}

          {/* LOGIN */}
          {mode === 'login' && (
            <form onSubmit={handleLogin} className="space-y-4">
              <input type="email" required value={loginForm.email} onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })} placeholder="Email" className="w-full px-3 py-2 border rounded-lg" />
              <input type={showPassword ? 'text' : 'password'} required value={loginForm.password} onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })} placeholder="Password" className="w-full px-3 py-2 border rounded-lg" />
              <button type="button" onClick={() => setShowPassword(!showPassword)}>{showPassword ? 'Hide' : 'Show'}</button>
              <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded-lg">{loading ? 'Signing In...' : 'Sign In'}</button>
              <button type="button" onClick={() => setMode('forgotPassword')} className="text-blue-600 text-sm mt-2">Forgot Password?</button>
              <p className="mt-2 text-sm">Don't have an account? <button onClick={switchMode} className="text-blue-600">Sign Up</button></p>
            </form>
          )}

          {/* REGISTER */}
          {mode === 'register' && (
            <form onSubmit={handleRegister} className="space-y-4">
              <input type="text" required placeholder="Name" value={registerForm.name} onChange={(e) => setRegisterForm({ ...registerForm, name: e.target.value })} className="w-full px-3 py-2 border rounded-lg" />
              <input type="email" required placeholder="Email" value={registerForm.email} onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })} className="w-full px-3 py-2 border rounded-lg" />
              <input type="text" required placeholder="Phone" value={registerForm.phone} onChange={(e) => setRegisterForm({ ...registerForm, phone: e.target.value })} className="w-full px-3 py-2 border rounded-lg" />
              <input type={showPassword ? 'text' : 'password'} required placeholder="Password" value={registerForm.password} onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })} className="w-full px-3 py-2 border rounded-lg" />
              <input type={showConfirmPassword ? 'text' : 'password'} required placeholder="Confirm Password" value={registerForm.confirmPassword} onChange={(e) => setRegisterForm({ ...registerForm, confirmPassword: e.target.value })} className="w-full px-3 py-2 border rounded-lg" />
              <button type="button" onClick={() => setShowPassword(!showPassword)}>{showPassword ? 'Hide' : 'Show'} Passwords</button>
              <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded-lg">{loading ? 'Creating Account...' : 'Create Account'}</button>
              <p className="mt-2 text-sm">Already have an account? <button onClick={switchMode} className="text-blue-600">Sign In</button></p>
            </form>
          )}

          {/* FORGOT PASSWORD */}
          {mode === 'forgotPassword' && (
            <form onSubmit={handleForgotPassword} className="space-y-4">
              <input type="email" required value={forgotForm.email} onChange={(e) => setForgotForm({ email: e.target.value })} placeholder="Enter your email" className="w-full px-3 py-2 border rounded-lg" />
              <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded-lg">{loading ? 'Sending OTP...' : 'Send OTP'}</button>
              <button type="button" onClick={() => setMode('login')} className="text-blue-600 text-sm mt-2">← Back to Sign In</button>
            </form>
          )}

          {/* VERIFY OTP */}
          {mode === 'verifyOtp' && (
            <form onSubmit={handleVerifyOtp} className="space-y-4">
              <p className="text-sm text-gray-600">OTP sent to {otpForm.email}</p>
              <input type="text" required value={otpForm.otp} onChange={(e) => setOtpForm({ ...otpForm, otp: e.target.value })} placeholder="Enter OTP" className="w-full px-3 py-2 border rounded-lg" />
              <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded-lg">{loading ? 'Verifying...' : 'Verify OTP'}</button>
              <button type="button" onClick={() => setMode('forgotPassword')} className="text-blue-600 text-sm mt-2">← Back</button>
            </form>
          )}

          {/* RESET PASSWORD */}
          {mode === 'resetPassword' && (
            <form onSubmit={handleResetPassword} className="space-y-4">
              <input type={showPassword ? 'text' : 'password'} required value={resetForm.password} onChange={(e) => setResetForm({ ...resetForm, password: e.target.value })} placeholder="New Password" className="w-full px-3 py-2 border rounded-lg" />
              <input type={showConfirmPassword ? 'text' : 'password'} required value={resetForm.confirmPassword} onChange={(e) => setResetForm({ ...resetForm, confirmPassword: e.target.value })} placeholder="Confirm New Password" className="w-full px-3 py-2 border rounded-lg" />
              <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded-lg">{loading ? 'Resetting...' : 'Reset Password'}</button>
              <button type="button" onClick={() => setMode('login')} className="text-blue-600 text-sm mt-2">← Back to Sign In</button>
            </form>
          )}

        </div>
      </div>
    </div>
  );
};

export default AuthModal;
