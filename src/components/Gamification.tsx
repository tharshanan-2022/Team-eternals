import React, { useState, useEffect } from 'react';
import { Trophy, Star, Gift, Play, Target, Zap, Award, Coins, X, CheckCircle, Wallet as WalletIcon } from 'lucide-react';
import { User } from '../types';
import MemoryGame from './games/MemoryGame';
import NumberGuessingGame from './games/NumberGuessingGame';
import ReactionTimeGame from './games/ReactionTimeGame';
import WordScrambleGame from './games/WordScrambleGame';
import Wallet from './Wallet';

interface Game {
  id: string;
  name: string;
  description: string;
  max_points: number;
  difficulty: 'easy' | 'medium' | 'hard';
  is_active: boolean;
}

interface Reward {
  id: string;
  name: string;
  description: string;
  points_required: number;
  discount_percentage: number;
  is_active: boolean;
}

interface GameSession {
  id: string;
  game_id: string;
  game_name: string;
  difficulty: string;
  points_earned: number;
  completed_at: string;
}

interface GamificationProfile {
  points: number;
  totalPointsEarned: number;
  rewardsEnabled: boolean;
  recentSessions: GameSession[];
  availableRewards: Reward[];
}

interface GamificationProps {
  user: User;
  onClose: () => void;
}

const Gamification: React.FC<GamificationProps> = ({ user, onClose }) => {
  const [profile, setProfile] = useState<GamificationProfile | null>(null);
  const [games, setGames] = useState<Game[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'games' | 'rewards' | 'vouchers' | 'wallet'>('dashboard');
  const [showWallet, setShowWallet] = useState(false);
  const [playingGame, setPlayingGame] = useState<string | null>(null);
  const [gameResult, setGameResult] = useState<{ points: number; message: string } | null>(null);
  const [currentGameView, setCurrentGameView] = useState<{ gameType: string; difficulty: 'easy' | 'medium' | 'hard' } | null>(null);

  const API_BASE_URL = 'http://localhost:5000/api';

  const getAuthToken = () => {
    return localStorage.getItem('taxi_booking_token');
  };

  const apiCall = async (endpoint: string, options: RequestInit = {}) => {
    const token = getAuthToken();
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(errorData.error || errorData.message || 'API request failed');
      } catch (parseError) {
        // If response is not JSON, use status text
        throw new Error(`Request failed: ${response.status} ${response.statusText}`);
      }
    }

    return response.json();
  };

  const loadGamificationData = async () => {
    try {
      setLoading(true);
      const [profileData, gamesData] = await Promise.all([
        apiCall('/gamification/profile'),
        apiCall('/gamification/games')
      ]);
      setProfile(profileData);
      setGames(gamesData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load gamification data');
    } finally {
      setLoading(false);
    }
  };

  const playGame = async (gameId: string, difficulty: 'easy' | 'medium' | 'hard' = 'medium') => {
    try {
      setPlayingGame(gameId);
      // Start game session
      await apiCall(`/gamification/games/${gameId}/start`, { method: 'POST' });
      
      // Find the game to get its name
      const game = games.find(g => g.id === gameId);
      if (!game) {
        throw new Error('Game not found');
      }
      
      // Map game names to game types
      const gameTypeMap: { [key: string]: string } = {
        'Number Memory': 'memory',
        'Color Match': 'memory', // This should be memory game for now
        'Speed Click': 'reaction-time',
        'Pattern Recognition': 'word-scramble',
        'Math Challenge': 'number-guessing'
      };
      
      const gameType = gameTypeMap[game.name] || 'memory';
      setCurrentGameView({ gameType, difficulty });
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start game');
      setPlayingGame(null);
    }
  };
  
  const handleGameComplete = async (score: number) => {
    try {
      if (!playingGame) return;
      
      const result = await apiCall(`/gamification/games/${playingGame}/complete`, {
        method: 'POST',
        body: JSON.stringify({ score })
      });
      
      setGameResult({
        points: result.pointsEarned,
        message: result.message
      });
      
      // Reload profile to update points
      await loadGamificationData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to complete game');
    } finally {
      setPlayingGame(null);
      setCurrentGameView(null);
    }
  };
  
  const handleBackToGames = () => {
    setCurrentGameView(null);
    setPlayingGame(null);
    setActiveTab('games');
  };

  const [redeemedRewards, setRedeemedRewards] = useState<any[]>([]);
  const [isRedeeming, setIsRedeeming] = useState<string | null>(null);

  const redeemReward = async (rewardId: string) => {
    try {
      setIsRedeeming(rewardId);
      const result = await apiCall('/gamification/redeem-reward', {
        method: 'POST',
        body: JSON.stringify({ rewardId })
      });
      
      alert(`${result.message}\n\nVoucher Code: ${result.reward.voucherCode}\nValue: $${result.reward.value}`);
      await loadGamificationData();
      await loadRedeemedRewards();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to redeem reward');
    } finally {
      setIsRedeeming(null);
    }
  };

  const loadRedeemedRewards = async () => {
    try {
      const result = await apiCall('/gamification/my-rewards');
      setRedeemedRewards(result.rewards);
    } catch (err) {
      console.error('Failed to load redeemed rewards:', err);
    }
  };

  useEffect(() => {
    loadGamificationData();
    loadRedeemedRewards();
  }, []);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'text-green-600 bg-green-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'hard': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getDifficultyIcon = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return <Star className="w-4 h-4" />;
      case 'medium': return <Target className="w-4 h-4" />;
      case 'hard': return <Zap className="w-4 h-4" />;
      default: return <Star className="w-4 h-4" />;
    }
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center">
        <div className="bg-white rounded-2xl p-8 max-w-md w-full mx-4">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
          </div>
          <p className="text-center mt-4 text-gray-600">Loading gamification data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center">
        <div className="bg-white rounded-2xl p-8 max-w-md w-full mx-4">
          <div className="text-center">
            <div className="text-red-500 mb-4">
              <X className="w-12 h-12 mx-auto" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Error</h3>
            <p className="text-gray-600 mb-4">{error}</p>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
        {/* Only show main content when no game is active */}
        {!currentGameView && (
          <>
            {/* Header */}
            <div className="bg-gradient-to-r from-primary-600 to-primary-700 text-white p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Trophy className="w-8 h-8" />
                  <div>
                    <h2 className="text-2xl font-bold">Game Center</h2>
                    <p className="text-primary-100">Earn points and unlock rewards!</p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="p-2 hover:bg-white/20 rounded-lg transition-colors"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-gray-200">
              <div className="flex">
                {[
                  { id: 'dashboard', label: 'Dashboard', icon: Trophy },
                  { id: 'games', label: 'Games', icon: Play },
                  { id: 'rewards', label: 'Rewards', icon: Gift },
                  { id: 'vouchers', label: 'My Vouchers', icon: Award }
                ].map(({ id, label, icon: Icon }) => (
                  <button
                    key={id}
                    onClick={() => setActiveTab(id as any)}
                    className={`flex items-center gap-2 px-6 py-4 font-medium transition-colors ${
                      activeTab === id
                        ? 'text-primary-600 border-b-2 border-primary-600 bg-primary-50'
                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                    {label}
                  </button>
                ))}
                <button
                  onClick={() => setShowWallet(true)}
                  className="flex items-center gap-2 px-6 py-4 font-medium transition-colors text-gray-600 hover:text-gray-900 hover:bg-gray-50"
                >
                  <WalletIcon className="w-5 h-5" />
                  Wallet
                </button>
              </div>
            </div>

            {/* Content */}
            <div className="p-6 overflow-y-auto max-h-[60vh]">
          {activeTab === 'dashboard' && profile && (
            <div className="space-y-6">
              {/* Stats Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6">
                  <div className="flex items-center gap-3">
                    <div className="p-3 bg-blue-600 rounded-lg">
                      <Coins className="w-6 h-6 text-white" />
                    </div>
                    <div>
                      <p className="text-blue-600 font-medium">Current Points</p>
                      <p className="text-2xl font-bold text-blue-900">{profile.points}</p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-xl p-6">
                  <div className="flex items-center gap-3">
                    <div className="p-3 bg-green-600 rounded-lg">
                      <Award className="w-6 h-6 text-white" />
                    </div>
                    <div>
                      <p className="text-green-600 font-medium">Total Earned</p>
                      <p className="text-2xl font-bold text-green-900">{profile.totalPointsEarned}</p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-6">
                  <div className="flex items-center gap-3">
                    <div className="p-3 bg-purple-600 rounded-lg">
                      <Gift className="w-6 h-6 text-white" />
                    </div>
                    <div>
                      <p className="text-purple-600 font-medium">Available Rewards</p>
                      <p className="text-2xl font-bold text-purple-900">{profile.availableRewards.length}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Recent Sessions */}
              {profile.recentSessions.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Game Sessions</h3>
                  <div className="space-y-3">
                    {profile.recentSessions.slice(0, 5).map((session) => (
                      <div key={session.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                        <div className="flex items-center gap-3">
                          <div className={`px-2 py-1 rounded-full text-xs font-medium ${getDifficultyColor(session.difficulty)}`}>
                            <div className="flex items-center gap-1">
                              {getDifficultyIcon(session.difficulty)}
                              {session.difficulty}
                            </div>
                          </div>
                          <div>
                            <p className="font-medium text-gray-900">{session.game_name}</p>
                            <p className="text-sm text-gray-600">{new Date(session.completed_at).toLocaleDateString()}</p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="font-semibold text-green-600">+{session.points_earned} points</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'games' && (
            <div className="space-y-6">
              <div className="text-center">
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Available Games</h3>
                <p className="text-gray-600">Play games to earn points and unlock rewards!</p>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {games.filter(game => game.is_active).map((game) => (
                  <div key={game.id} className="group relative bg-gradient-to-br from-white to-gray-50 border border-gray-200 rounded-2xl p-6 hover:shadow-2xl hover:scale-[1.02] transition-all duration-300 overflow-hidden">
                    {/* Background Pattern */}
                    <div className="absolute inset-0 opacity-5">
                      <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary-400 to-primary-600 rounded-full transform translate-x-16 -translate-y-16"></div>
                      <div className="absolute bottom-0 left-0 w-24 h-24 bg-gradient-to-tr from-blue-400 to-purple-500 rounded-full transform -translate-x-12 translate-y-12"></div>
                    </div>
                    
                    {/* Game Header */}
                    <div className="relative z-10 mb-6">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <h4 className="text-xl font-bold text-gray-900 mb-2 group-hover:text-primary-700 transition-colors">{game.name}</h4>
                          <p className="text-gray-600 text-sm leading-relaxed">{game.description}</p>
                        </div>
                        <div className="ml-4 flex flex-col items-center">
                          <div className="w-12 h-12 bg-gradient-to-br from-primary-500 to-primary-600 rounded-xl flex items-center justify-center mb-2 group-hover:scale-110 transition-transform duration-300">
                            <Play className="w-6 h-6 text-white" />
                          </div>
                          <span className="text-xs text-gray-500 font-medium">Max {game.max_points}pts</span>
                        </div>
                      </div>
                    </div>
                    
                    {/* Difficulty Selection */}
                    <div className="relative z-10 mb-4">
                      <p className="text-sm font-semibold text-gray-700 mb-4 flex items-center gap-2">
                        <Target className="w-4 h-4" />
                        Choose Your Challenge:
                      </p>
                      <div className="grid grid-cols-3 gap-3">
                        {['easy', 'medium', 'hard'].map((difficulty, index) => {
                          const difficultyConfig = {
                            easy: {
                              gradient: 'from-green-400 to-green-600',
                              hoverGradient: 'hover:from-green-500 hover:to-green-700',
                              shadow: 'shadow-green-200',
                              hoverShadow: 'hover:shadow-green-300',
                              icon: '🌱',
                              label: 'Easy',
                              description: 'Beginner'
                            },
                            medium: {
                              gradient: 'from-yellow-400 to-orange-500',
                              hoverGradient: 'hover:from-yellow-500 hover:to-orange-600',
                              shadow: 'shadow-yellow-200',
                              hoverShadow: 'hover:shadow-yellow-300',
                              icon: '⚡',
                              label: 'Medium',
                              description: 'Intermediate'
                            },
                            hard: {
                              gradient: 'from-red-500 to-red-700',
                              hoverGradient: 'hover:from-red-600 hover:to-red-800',
                              shadow: 'shadow-red-200',
                              hoverShadow: 'hover:shadow-red-300',
                              icon: '🔥',
                              label: 'Hard',
                              description: 'Expert'
                            }
                          }[difficulty as keyof typeof difficultyConfig];
                          
                          return (
                            <button
                              key={difficulty}
                              onClick={() => playGame(game.id, difficulty as 'easy' | 'medium' | 'hard')}
                              disabled={playingGame === game.id}
                              className={`
                                group/btn relative overflow-hidden
                                bg-gradient-to-br ${difficultyConfig.gradient} ${difficultyConfig.hoverGradient}
                                text-white font-bold py-4 px-3 rounded-xl
                                transform transition-all duration-300 ease-out
                                hover:scale-105 hover:-translate-y-1
                                shadow-lg ${difficultyConfig.shadow} ${difficultyConfig.hoverShadow}
                                disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none
                                focus:outline-none focus:ring-4 focus:ring-opacity-50
                                animate-pulse-slow
                              `}
                              style={{
                                animationDelay: `${index * 0.1}s`,
                                animationDuration: '2s'
                              }}
                            >
                              {/* Button Background Animation */}
                              <div className="absolute inset-0 bg-white opacity-0 group-hover/btn:opacity-20 transition-opacity duration-300"></div>
                              
                              {/* Button Content */}
                              <div className="relative z-10 flex flex-col items-center gap-1">
                                <span className="text-lg">{difficultyConfig.icon}</span>
                                <span className="text-xs font-bold uppercase tracking-wide">{difficultyConfig.label}</span>
                                <span className="text-xs opacity-90">{difficultyConfig.description}</span>
                              </div>
                              
                              {/* Shine Effect */}
                              <div className="absolute inset-0 -top-2 -left-2 w-4 h-full bg-white opacity-30 transform rotate-12 translate-x-[-100%] group-hover/btn:translate-x-[300%] transition-transform duration-700 ease-out"></div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                    
                    {/* Loading State */}
                    {playingGame === game.id && (
                      <div className="relative z-10 flex items-center justify-center py-4">
                        <div className="flex items-center gap-3 px-4 py-2 bg-blue-50 rounded-full border border-blue-200">
                          <div className="relative">
                            <div className="animate-spin rounded-full h-5 w-5 border-2 border-blue-600 border-t-transparent"></div>
                            <div className="absolute inset-0 animate-ping rounded-full h-5 w-5 border border-blue-400 opacity-20"></div>
                          </div>
                          <span className="text-sm font-medium text-blue-700 animate-pulse">Launching Game...</span>
                        </div>
                      </div>
                    )}
                    
                    {/* Hover Glow Effect */}
                    <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-primary-400/0 via-primary-400/5 to-primary-400/0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'rewards' && profile && (
            <div className="space-y-6">
              <div className="text-center">
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Available Rewards</h3>
                <p className="text-gray-600">Redeem your points for booking discounts!</p>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {profile.availableRewards.map((reward) => (
                  <div key={reward.id} className="border border-gray-200 rounded-xl p-6 hover:shadow-lg transition-shadow">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h4 className="text-lg font-semibold text-gray-900">{reward.name}</h4>
                        <p className="text-gray-600 text-sm mt-1">{reward.description}</p>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl font-bold text-green-600">{reward.discount_percentage}%</div>
                        <div className="text-xs text-gray-500">OFF</div>
                      </div>
                    </div>
                    
                    <div className="space-y-3">
                      <div className="text-sm text-gray-600">
                        Cost: <span className="font-semibold text-primary-600">{reward.points_required} points</span>
                      </div>
                      <div className="flex flex-col gap-2">
                        <button
                          onClick={() => redeemReward(reward.id)}
                          disabled={profile.points < reward.points_required || isRedeeming === reward.id}
                          className="flex items-center justify-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {isRedeeming === reward.id ? (
                            <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
                          ) : (
                            <Gift className="w-4 h-4" />
                          )}
                          {isRedeeming === reward.id ? 'Redeeming...' : 
                           profile.points >= reward.points_required ? 'Redeem with Points' : 'Not Enough Points'}
                        </button>
                        <button
                          onClick={() => setShowWallet(true)}
                          className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm"
                        >
                          <WalletIcon className="w-4 h-4" />
                          Convert Points to Money
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              
              {profile.availableRewards.length === 0 && (
                <div className="text-center py-12">
                  <Gift className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No Rewards Available</h3>
                  <p className="text-gray-600">Play more games to earn points and unlock rewards!</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'vouchers' && (
            <div className="space-y-6">
              <div className="text-center">
                <h3 className="text-lg font-semibold text-gray-900 mb-2">My Vouchers</h3>
                <p className="text-gray-600">Your redeemed rewards and voucher codes</p>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {redeemedRewards.map((voucher) => (
                  <div key={voucher.id} className="border border-gray-200 rounded-xl p-6 hover:shadow-lg transition-shadow">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h4 className="text-lg font-semibold text-gray-900">{voucher.reward_name}</h4>
                        <p className="text-gray-600 text-sm mt-1">{voucher.reward_description}</p>
                      </div>
                      <div className="text-right">
                        <div className={`px-2 py-1 rounded-full text-xs font-medium ${
                          voucher.status === 'redeemed' ? 'bg-green-100 text-green-800' :
                          voucher.status === 'used' ? 'bg-gray-100 text-gray-800' :
                          'bg-red-100 text-red-800'
                        }`}>
                          {voucher.status.charAt(0).toUpperCase() + voucher.status.slice(1)}
                        </div>
                      </div>
                    </div>
                    
                    <div className="space-y-3">
                      <div className="text-sm text-gray-600">
                        Value: <span className="font-semibold text-green-600">${voucher.value}</span>
                      </div>
                      <div className="text-sm text-gray-600">
                        Points Used: <span className="font-semibold text-primary-600">{voucher.points_used}</span>
                      </div>
                      <div className="bg-gray-50 rounded-lg p-3">
                        <div className="text-xs text-gray-500 mb-1">Voucher Code</div>
                        <div className="font-mono text-sm font-bold text-gray-900 break-all">{voucher.voucher_code}</div>
                      </div>
                      <div className="text-xs text-gray-500">
                        Redeemed: {new Date(voucher.created_at).toLocaleDateString()}
                        {voucher.used_at && (
                          <span className="block">Used: {new Date(voucher.used_at).toLocaleDateString()}</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              
              {redeemedRewards.length === 0 && (
                <div className="text-center py-12">
                  <Award className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No Vouchers Yet</h3>
                  <p className="text-gray-600">Redeem rewards to get voucher codes!</p>
                </div>
              )}
            </div>
          )}
            </div>
          </>
        )}
      </div>
      
      {/* Individual Game Components */}
      {currentGameView && !gameResult && (
        <div className="fixed inset-0 z-70">
          {currentGameView.gameType === 'memory' && (
            <MemoryGame
              onBack={handleBackToGames}
              onGameComplete={handleGameComplete}
              difficulty={currentGameView.difficulty}
            />
          )}
          {currentGameView.gameType === 'number-guessing' && (
            <NumberGuessingGame
              onBack={handleBackToGames}
              onGameComplete={handleGameComplete}
              difficulty={currentGameView.difficulty}
            />
          )}
          {currentGameView.gameType === 'reaction-time' && (
            <ReactionTimeGame
              onBack={handleBackToGames}
              onGameComplete={handleGameComplete}
              difficulty={currentGameView.difficulty}
            />
          )}
          {currentGameView.gameType === 'word-scramble' && (
            <WordScrambleGame
              onBack={handleBackToGames}
              onGameComplete={handleGameComplete}
              difficulty={currentGameView.difficulty}
            />
          )}
        </div>
      )}
      
      {/* Game Result Modal - Highest z-index to appear above everything */}
      {gameResult && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-[100] flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-8 max-w-md w-full mx-4 text-center shadow-2xl">
            <div className="text-green-500 mb-4">
              <CheckCircle className="w-16 h-16 mx-auto" />
            </div>
            <h3 className="text-xl font-bold text-gray-900 mb-2">Game Complete!</h3>
            <p className="text-gray-600 mb-4">{gameResult.message}</p>
            <div className="text-3xl font-bold text-green-600 mb-6">+{gameResult.points} Points</div>
            <button
              onClick={() => {
                setGameResult(null);
                setCurrentGameView(null);
                setActiveTab('dashboard');
              }}
              className="px-6 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium"
            >
              Continue
            </button>
          </div>
        </div>
      )}
      
      {/* Wallet Modal */}
      {showWallet && (
        <Wallet onClose={() => setShowWallet(false)} />
      )}
    </div>
  );
};

export default Gamification;