import React, { useState, useEffect } from 'react';
import { Wallet as WalletIcon, CreditCard, ArrowUpCircle, ArrowDownCircle, Coins, DollarSign, RefreshCw, Settings, History, Plus } from 'lucide-react';

interface WalletTransaction {
  id: number;
  transaction_type: 'credit' | 'debit' | 'reward_conversion';
  amount: number;
  balance_after: number;
  description: string;
  reference_type: 'topup' | 'booking' | 'reward' | 'refund';
  status: 'pending' | 'completed' | 'failed' | 'cancelled';
  created_at: string;
}

interface TopupMethod {
  id: number;
  name: string;
  type: string;
  description: string;
  min_amount: number;
  max_amount: number;
  processing_fee_percentage: number;
  processing_fee_fixed: number;
  is_active: boolean;
}

interface WalletSettings {
  pointsToMoneyRate: number;
  minConversionPoints: number;
  maxDailyConversion: number;
  maxBalance: number;
}

interface WalletData {
  balance: number;
  enabled: boolean;
  points: number;
  transactions: WalletTransaction[];
  settings: WalletSettings;
}

interface WalletProps {
  onClose: () => void;
}

const Wallet: React.FC<WalletProps> = ({ onClose }) => {
  const [walletData, setWalletData] = useState<WalletData | null>(null);
  const [topupMethods, setTopupMethods] = useState<TopupMethod[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'topup' | 'convert' | 'history'>('overview');
  const [showTopupModal, setShowTopupModal] = useState(false);
  const [showConvertModal, setShowConvertModal] = useState(false);
  const [topupAmount, setTopupAmount] = useState('');
  const [selectedMethod, setSelectedMethod] = useState<number | null>(null);
  const [convertPoints, setConvertPoints] = useState('');
  const [paymentDetails, setPaymentDetails] = useState({
    // Credit/Debit Card fields
    cardNumber: '',
    expiryDate: '',
    cvv: '',
    cardholderName: '',
    // Bank Transfer fields
    bankName: '',
    accountNumber: '',
    routingNumber: '',
    accountHolderName: '',
    // Digital Wallet fields
    walletProvider: '',
    walletId: '',
    phoneNumber: '',
    email: ''
  });

  useEffect(() => {
    fetchWalletData();
    fetchTopupMethods();
  }, []);

  const apiCall = async (url: string, options: RequestInit = {}) => {
    const token = localStorage.getItem('taxi_booking_token');
    const response = await fetch(`http://localhost:5000/api${url}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers,
      },
    });

    if (!response.ok) {
      let errorData;
      try {
        errorData = await response.json();
      } catch {
        errorData = { error: response.statusText };
      }
      throw new Error(errorData.error || errorData.message || 'API request failed');
    }

    return response.json();
  };

  const fetchWalletData = async () => {
    try {
      setLoading(true);
      const data = await apiCall('/wallet/balance');
      setWalletData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch wallet data');
    } finally {
      setLoading(false);
    }
  };

  const fetchTopupMethods = async () => {
    try {
      const methods = await apiCall('/wallet/topup-methods');
      setTopupMethods(methods);
    } catch (err) {
      console.error('Failed to fetch top-up methods:', err);
    }
  };

  const handleTopup = async () => {
    if (!selectedMethod || !topupAmount) {
      setError('Please select a payment method and enter an amount');
      return;
    }

    try {
      setLoading(true);
      const selectedMethodDetails = getSelectedMethodDetails();
      const methodType = selectedMethodDetails?.type;
      
      // Prepare payment details based on method type
      let processedPaymentDetails = {};
      
      if (methodType === 'credit_card' || methodType === 'debit_card') {
        processedPaymentDetails = {
          cardNumber: paymentDetails.cardNumber,
          expiryDate: paymentDetails.expiryDate,
          cvv: paymentDetails.cvv,
          cardholderName: paymentDetails.cardholderName
        };
      } else if (methodType === 'bank_transfer') {
        processedPaymentDetails = {
          bankName: paymentDetails.bankName,
          accountNumber: paymentDetails.accountNumber,
          routingNumber: paymentDetails.routingNumber,
          accountHolderName: paymentDetails.accountHolderName
        };
      } else if (methodType === 'digital_wallet') {
        processedPaymentDetails = {
          walletProvider: paymentDetails.walletProvider,
          walletId: paymentDetails.walletId,
          phoneNumber: paymentDetails.phoneNumber,
          email: paymentDetails.email
        };
      }

      const result = await apiCall('/wallet/topup', {
        method: 'POST',
        body: JSON.stringify({
          amount: parseFloat(topupAmount),
          methodId: selectedMethod,
          paymentDetails: processedPaymentDetails
        })
      });

      setShowTopupModal(false);
      setTopupAmount('');
      setSelectedMethod(null);
      resetPaymentDetails();
      await fetchWalletData();
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Top-up failed');
    } finally {
      setLoading(false);
    }
  };

  const handleConvertPoints = async () => {
    if (!convertPoints) {
      setError('Please enter the number of points to convert');
      return;
    }

    try {
      setLoading(true);
      const result = await apiCall('/wallet/convert-points', {
        method: 'POST',
        body: JSON.stringify({
          points: parseInt(convertPoints)
        })
      });

      setShowConvertModal(false);
      setConvertPoints('');
      await fetchWalletData();
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Point conversion failed');
    } finally {
      setLoading(false);
    }
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(amount);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getSelectedMethodDetails = () => {
    return topupMethods.find(method => method.id === selectedMethod);
  };

  const resetPaymentDetails = () => {
    setPaymentDetails({
      cardNumber: '',
      expiryDate: '',
      cvv: '',
      cardholderName: '',
      bankName: '',
      accountNumber: '',
      routingNumber: '',
      accountHolderName: '',
      walletProvider: '',
      walletId: '',
      phoneNumber: '',
      email: ''
    });
  };

  const getTransactionIcon = (type: string, referenceType: string) => {
    if (type === 'credit') {
      return <ArrowUpCircle className="w-5 h-5 text-green-500" />;
    } else if (type === 'debit') {
      return <ArrowDownCircle className="w-5 h-5 text-red-500" />;
    } else {
      return <Coins className="w-5 h-5 text-blue-500" />;
    }
  };

  if (loading && !walletData) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-8 max-w-md w-full mx-4">
          <div className="flex items-center justify-center">
            <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
            <span className="ml-2 text-lg">Loading wallet...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg max-w-4xl w-full mx-4 max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <WalletIcon className="w-8 h-8 mr-3" />
              <div>
                <h2 className="text-2xl font-bold">Digital Wallet</h2>
                <p className="text-blue-100">Manage your digital money</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-white hover:text-gray-200 text-2xl font-bold"
            >
              ×
            </button>
          </div>

          {walletData && (
            <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-white bg-opacity-20 rounded-lg p-4">
                <div className="flex items-center">
                  <DollarSign className="w-6 h-6 mr-2" />
                  <div>
                    <p className="text-sm text-blue-100">Wallet Balance</p>
                    <p className="text-2xl font-bold">{formatCurrency(walletData.balance)}</p>
                  </div>
                </div>
              </div>
              <div className="bg-white bg-opacity-20 rounded-lg p-4">
                <div className="flex items-center">
                  <Coins className="w-6 h-6 mr-2" />
                  <div>
                    <p className="text-sm text-blue-100">Available Points</p>
                    <p className="text-2xl font-bold">{walletData.points.toLocaleString()}</p>
                  </div>
                </div>
              </div>
              <div className="bg-white bg-opacity-20 rounded-lg p-4">
                <div className="flex items-center">
                  <Settings className="w-6 h-6 mr-2" />
                  <div>
                    <p className="text-sm text-blue-100">Status</p>
                    <p className="text-lg font-semibold">
                      {walletData.enabled ? 'Active' : 'Disabled'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 mx-6 mt-4 rounded">
            {error}
            <button
              onClick={() => setError(null)}
              className="float-right text-red-500 hover:text-red-700"
            >
              ×
            </button>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            {[
              { id: 'overview', label: 'Overview', icon: WalletIcon },
              { id: 'topup', label: 'Top Up', icon: Plus },
              { id: 'convert', label: 'Convert Points', icon: Coins },
              { id: 'history', label: 'History', icon: History }
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id as any)}
                className={`py-4 px-2 border-b-2 font-medium text-sm flex items-center ${
                  activeTab === id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="w-4 h-4 mr-2" />
                {label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="p-6 overflow-y-auto max-h-96">
          {activeTab === 'overview' && walletData && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-gray-50 rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-3">Quick Actions</h3>
                  <div className="space-y-2">
                    <button
                      onClick={() => setShowTopupModal(true)}
                      className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 flex items-center justify-center"
                    >
                      <Plus className="w-4 h-4 mr-2" />
                      Add Money
                    </button>
                    <button
                      onClick={() => setShowConvertModal(true)}
                      className="w-full bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 flex items-center justify-center"
                      disabled={walletData.points < walletData.settings.minConversionPoints}
                    >
                      <Coins className="w-4 h-4 mr-2" />
                      Convert Points
                    </button>
                  </div>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <h3 className="text-lg font-semibold mb-3">Conversion Info</h3>
                  <div className="space-y-2 text-sm">
                    <p><span className="font-medium">Rate:</span> {walletData.settings.pointsToMoneyRate} points = $1</p>
                    <p><span className="font-medium">Min Conversion:</span> {walletData.settings.minConversionPoints} points</p>
                    <p><span className="font-medium">Daily Limit:</span> {formatCurrency(walletData.settings.maxDailyConversion)}</p>
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-lg font-semibold mb-3">Recent Transactions</h3>
                <div className="space-y-2">
                  {walletData.transactions.slice(0, 5).map((transaction) => (
                    <div key={transaction.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center">
                        {getTransactionIcon(transaction.transaction_type, transaction.reference_type)}
                        <div className="ml-3">
                          <p className="font-medium">{transaction.description}</p>
                          <p className="text-sm text-gray-500">{formatDate(transaction.created_at)}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className={`font-semibold ${
                          transaction.transaction_type === 'credit' ? 'text-green-600' : 'text-red-600'
                        }`}>
                          {transaction.transaction_type === 'credit' ? '+' : '-'}{formatCurrency(transaction.amount)}
                        </p>
                        <p className="text-sm text-gray-500">
                          Balance: {formatCurrency(transaction.balance_after)}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'topup' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold">Add Money to Wallet</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {topupMethods.map((method) => (
                  <div
                    key={method.id}
                    onClick={() => {
                      setSelectedMethod(method.id);
                      setShowTopupModal(true);
                    }}
                    className="border border-gray-200 rounded-lg p-4 hover:border-blue-500 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center mb-2">
                      <CreditCard className="w-6 h-6 mr-3 text-blue-500" />
                      <h4 className="font-semibold">{method.name}</h4>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{method.description}</p>
                    <div className="text-xs text-gray-500">
                      <p>Range: {formatCurrency(method.min_amount)} - {formatCurrency(method.max_amount)}</p>
                      <p>Fee: {method.processing_fee_percentage}% + {formatCurrency(method.processing_fee_fixed)}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'convert' && walletData && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold">Convert Points to Money</h3>
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-600">Available Points</p>
                    <p className="text-2xl font-bold text-blue-600">{walletData.points.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Conversion Rate</p>
                    <p className="text-lg font-semibold">{walletData.settings.pointsToMoneyRate} points = $1</p>
                  </div>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Points to Convert
                  </label>
                  <input
                    type="number"
                    value={convertPoints}
                    onChange={(e) => setConvertPoints(e.target.value)}
                    min={walletData.settings.minConversionPoints}
                    max={walletData.points}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder={`Minimum ${walletData.settings.minConversionPoints} points`}
                  />
                </div>
                {convertPoints && (
                  <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                    <p className="text-sm text-green-700">
                      You will receive: <span className="font-semibold">
                        {formatCurrency(parseInt(convertPoints) / walletData.settings.pointsToMoneyRate)}
                      </span>
                    </p>
                  </div>
                )}
                <button
                  onClick={handleConvertPoints}
                  disabled={!convertPoints || parseInt(convertPoints) < walletData.settings.minConversionPoints || loading}
                  className="w-full bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {loading ? 'Converting...' : 'Convert Points'}
                </button>
              </div>
            </div>
          )}

          {activeTab === 'history' && walletData && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Transaction History</h3>
              <div className="space-y-2">
                {walletData.transactions.map((transaction) => (
                  <div key={transaction.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                    <div className="flex items-center">
                      {getTransactionIcon(transaction.transaction_type, transaction.reference_type)}
                      <div className="ml-3">
                        <p className="font-medium">{transaction.description}</p>
                        <p className="text-sm text-gray-500">
                          {formatDate(transaction.created_at)} • {transaction.status}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className={`font-semibold ${
                        transaction.transaction_type === 'credit' ? 'text-green-600' : 'text-red-600'
                      }`}>
                        {transaction.transaction_type === 'credit' ? '+' : '-'}{formatCurrency(transaction.amount)}
                      </p>
                      <p className="text-sm text-gray-500">
                        Balance: {formatCurrency(transaction.balance_after)}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Top-up Modal */}
        {showTopupModal && selectedMethod && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-60">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold mb-4">Add Money to Wallet</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Amount
                  </label>
                  <input
                    type="number"
                    value={topupAmount}
                    onChange={(e) => setTopupAmount(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Enter amount"
                  />
                </div>
                
                {/* Payment Details */}
                {(() => {
                  const selectedMethodDetails = getSelectedMethodDetails();
                  const methodType = selectedMethodDetails?.type;

                  if (methodType === 'credit_card' || methodType === 'debit_card') {
                    return (
                      <div className="space-y-3">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Cardholder Name
                          </label>
                          <input
                            type="text"
                            value={paymentDetails.cardholderName}
                            onChange={(e) => setPaymentDetails({...paymentDetails, cardholderName: e.target.value})}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="John Doe"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Card Number
                          </label>
                          <input
                            type="text"
                            value={paymentDetails.cardNumber}
                            onChange={(e) => setPaymentDetails({...paymentDetails, cardNumber: e.target.value})}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="1234 5678 9012 3456"
                          />
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                              Expiry Date
                            </label>
                            <input
                              type="text"
                              value={paymentDetails.expiryDate}
                              onChange={(e) => setPaymentDetails({...paymentDetails, expiryDate: e.target.value})}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                              placeholder="MM/YY"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                              CVV
                            </label>
                            <input
                              type="text"
                              value={paymentDetails.cvv}
                              onChange={(e) => setPaymentDetails({...paymentDetails, cvv: e.target.value})}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                              placeholder="123"
                            />
                          </div>
                        </div>
                      </div>
                    );
                  }

                  if (methodType === 'bank_transfer') {
                    return (
                      <div className="space-y-3">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Account Holder Name
                          </label>
                          <input
                            type="text"
                            value={paymentDetails.accountHolderName}
                            onChange={(e) => setPaymentDetails({...paymentDetails, accountHolderName: e.target.value})}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="John Doe"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Bank Name
                          </label>
                          <input
                            type="text"
                            value={paymentDetails.bankName}
                            onChange={(e) => setPaymentDetails({...paymentDetails, bankName: e.target.value})}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="Bank of America"
                          />
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                              Account Number
                            </label>
                            <input
                              type="text"
                              value={paymentDetails.accountNumber}
                              onChange={(e) => setPaymentDetails({...paymentDetails, accountNumber: e.target.value})}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                              placeholder="1234567890"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                              Routing Number
                            </label>
                            <input
                              type="text"
                              value={paymentDetails.routingNumber}
                              onChange={(e) => setPaymentDetails({...paymentDetails, routingNumber: e.target.value})}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                              placeholder="021000021"
                            />
                          </div>
                        </div>
                        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                          <p className="text-sm text-yellow-700">
                            <strong>Note:</strong> Bank transfers may take 1-3 business days to process. You will receive a confirmation email with transfer instructions.
                          </p>
                        </div>
                      </div>
                    );
                  }

                  if (methodType === 'digital_wallet') {
                    return (
                      <div className="space-y-3">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Digital Wallet Provider
                          </label>
                          <select
                            value={paymentDetails.walletProvider}
                            onChange={(e) => setPaymentDetails({...paymentDetails, walletProvider: e.target.value})}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                          >
                            <option value="">Select Provider</option>
                            <option value="paypal">PayPal</option>
                            <option value="apple_pay">Apple Pay</option>
                            <option value="google_pay">Google Pay</option>
                            <option value="venmo">Venmo</option>
                            <option value="cashapp">Cash App</option>
                            <option value="zelle">Zelle</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Email Address
                          </label>
                          <input
                            type="email"
                            value={paymentDetails.email}
                            onChange={(e) => setPaymentDetails({...paymentDetails, email: e.target.value})}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="john@example.com"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Phone Number
                          </label>
                          <input
                            type="tel"
                            value={paymentDetails.phoneNumber}
                            onChange={(e) => setPaymentDetails({...paymentDetails, phoneNumber: e.target.value})}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            placeholder="(555) 123-4567"
                          />
                        </div>
                        {paymentDetails.walletProvider && (
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                              {paymentDetails.walletProvider === 'paypal' ? 'PayPal Email' :
                               paymentDetails.walletProvider === 'venmo' ? 'Venmo Username' :
                               paymentDetails.walletProvider === 'cashapp' ? 'Cash App Username' :
                               paymentDetails.walletProvider === 'zelle' ? 'Zelle Email/Phone' :
                               'Wallet ID'}
                            </label>
                            <input
                              type="text"
                              value={paymentDetails.walletId}
                              onChange={(e) => setPaymentDetails({...paymentDetails, walletId: e.target.value})}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                              placeholder={
                                paymentDetails.walletProvider === 'paypal' ? 'paypal@example.com' :
                                paymentDetails.walletProvider === 'venmo' ? '@username' :
                                paymentDetails.walletProvider === 'cashapp' ? '$username' :
                                paymentDetails.walletProvider === 'zelle' ? 'email@example.com' :
                                'Enter wallet ID'
                              }
                            />
                          </div>
                        )}
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                          <p className="text-sm text-blue-700">
                            <strong>Note:</strong> You will be redirected to {paymentDetails.walletProvider || 'your selected provider'} to complete the payment securely.
                          </p>
                        </div>
                      </div>
                    );
                  }

                  return (
                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                      <p className="text-sm text-gray-600">Please select a payment method to continue.</p>
                    </div>
                  );
                })()}
                
                <div className="flex space-x-3">
                  <button
                    onClick={() => {
                      setShowTopupModal(false);
                      setTopupAmount('');
                      setSelectedMethod(null);
                      resetPaymentDetails();
                    }}
                    className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleTopup}
                    disabled={!topupAmount || loading}
                    className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 disabled:bg-gray-400"
                  >
                    {loading ? 'Processing...' : 'Add Money'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Convert Points Modal */}
        {showConvertModal && walletData && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-60">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold mb-4">Convert Points to Money</h3>
              <div className="space-y-4">
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                  <p className="text-sm text-blue-700">
                    Available Points: <span className="font-semibold">{walletData.points.toLocaleString()}</span>
                  </p>
                  <p className="text-sm text-blue-700">
                    Rate: {walletData.settings.pointsToMoneyRate} points = $1
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Points to Convert
                  </label>
                  <input
                    type="number"
                    value={convertPoints}
                    onChange={(e) => setConvertPoints(e.target.value)}
                    min={walletData.settings.minConversionPoints}
                    max={walletData.points}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder={`Minimum ${walletData.settings.minConversionPoints} points`}
                  />
                </div>
                {convertPoints && (
                  <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                    <p className="text-sm text-green-700">
                      You will receive: <span className="font-semibold">
                        {formatCurrency(parseInt(convertPoints) / walletData.settings.pointsToMoneyRate)}
                      </span>
                    </p>
                  </div>
                )}
                <div className="flex space-x-3">
                  <button
                    onClick={() => {
                      setShowConvertModal(false);
                      setConvertPoints('');
                    }}
                    className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleConvertPoints}
                    disabled={!convertPoints || parseInt(convertPoints) < walletData.settings.minConversionPoints || loading}
                    className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 disabled:bg-gray-400"
                  >
                    {loading ? 'Converting...' : 'Convert'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Wallet;