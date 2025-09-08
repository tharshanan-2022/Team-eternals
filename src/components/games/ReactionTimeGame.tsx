import React, { useState, useEffect, useCallback } from 'react';
import { ArrowLeft, RotateCcw, Trophy, Clock, Zap, Target } from 'lucide-react';

interface ReactionTimeGameProps {
  onBack: () => void;
  onGameComplete: (score: number) => void;
  difficulty: 'easy' | 'medium' | 'hard';
}

interface Round {
  id: number;
  reactionTime: number;
  success: boolean;
}

type GameState = 'waiting' | 'ready' | 'go' | 'clicked' | 'failed' | 'completed';

const ReactionTimeGame: React.FC<ReactionTimeGameProps> = ({ onBack, onGameComplete, difficulty }) => {
  const [gameState, setGameState] = useState<GameState>('waiting');
  const [currentRound, setCurrentRound] = useState(1);
  const [rounds, setRounds] = useState<Round[]>([]);
  const [startTime, setStartTime] = useState(0);
  const [reactionTime, setReactionTime] = useState(0);
  const [timeoutId, setTimeoutId] = useState<NodeJS.Timeout | null>(null);
  const [score, setScore] = useState(0);
  const [averageTime, setAverageTime] = useState(0);
  const [bestTime, setBestTime] = useState(0);
  const [gameCompleted, setGameCompleted] = useState(false);

  // Game configuration based on difficulty
  const getGameConfig = () => {
    switch (difficulty) {
      case 'easy': 
        return { 
          totalRounds: 5,
          minDelay: 2000,
          maxDelay: 5000,
          baseScore: 100,
          perfectTime: 300
        };
      case 'medium': 
        return { 
          totalRounds: 7,
          minDelay: 1500,
          maxDelay: 4000,
          baseScore: 150,
          perfectTime: 250
        };
      case 'hard': 
        return { 
          totalRounds: 10,
          minDelay: 1000,
          maxDelay: 3000,
          baseScore: 200,
          perfectTime: 200
        };
      default: 
        return { 
          totalRounds: 5,
          minDelay: 2000,
          maxDelay: 5000,
          baseScore: 100,
          perfectTime: 300
        };
    }
  };

  const config = getGameConfig();

  // Initialize game
  const initializeGame = () => {
    setGameState('waiting');
    setCurrentRound(1);
    setRounds([]);
    setReactionTime(0);
    setScore(0);
    setAverageTime(0);
    setBestTime(0);
    setGameCompleted(false);
    if (timeoutId) {
      clearTimeout(timeoutId);
      setTimeoutId(null);
    }
  };

  // Start a new round
  const startRound = useCallback(() => {
    if (gameCompleted) return;
    
    setGameState('ready');
    setReactionTime(0);
    
    // Random delay before showing green
    const delay = Math.random() * (config.maxDelay - config.minDelay) + config.minDelay;
    
    const timeout = setTimeout(() => {
      setGameState('go');
      setStartTime(Date.now());
    }, delay);
    
    setTimeoutId(timeout);
  }, [config.maxDelay, config.minDelay, gameCompleted]);

  // Handle click during game
  const handleClick = useCallback(() => {
    if (gameState === 'ready') {
      // Clicked too early
      setGameState('failed');
      if (timeoutId) {
        clearTimeout(timeoutId);
        setTimeoutId(null);
      }
      
      const newRound: Round = {
        id: currentRound,
        reactionTime: 0,
        success: false
      };
      
      setRounds(prev => [...prev, newRound]);
      
      setTimeout(() => {
        if (currentRound >= config.totalRounds) {
          completeGame([...rounds, newRound]);
        } else {
          setCurrentRound(prev => prev + 1);
          startRound();
        }
      }, 1500);
      
    } else if (gameState === 'go') {
      // Successful click
      const endTime = Date.now();
      const reaction = endTime - startTime;
      setReactionTime(reaction);
      setGameState('clicked');
      
      const newRound: Round = {
        id: currentRound,
        reactionTime: reaction,
        success: true
      };
      
      setRounds(prev => [...prev, newRound]);
      
      setTimeout(() => {
        if (currentRound >= config.totalRounds) {
          completeGame([...rounds, newRound]);
        } else {
          setCurrentRound(prev => prev + 1);
          startRound();
        }
      }, 1500);
    }
  }, [gameState, timeoutId, startTime, currentRound, config.totalRounds, rounds, startRound]);

  // Complete the game and calculate score
  const completeGame = (finalRounds: Round[]) => {
    const successfulRounds = finalRounds.filter(r => r.success);
    const totalTime = successfulRounds.reduce((sum, r) => sum + r.reactionTime, 0);
    const avgTime = successfulRounds.length > 0 ? totalTime / successfulRounds.length : 0;
    const best = successfulRounds.length > 0 ? Math.min(...successfulRounds.map(r => r.reactionTime)) : 0;
    
    setAverageTime(avgTime);
    setBestTime(best);
    
    // Calculate score
    let finalScore = 0;
    successfulRounds.forEach(round => {
      const timeBonus = Math.max(0, config.perfectTime - round.reactionTime);
      finalScore += config.baseScore + timeBonus;
    });
    
    // Bonus for completing all rounds successfully
    if (successfulRounds.length === config.totalRounds) {
      finalScore += config.baseScore;
    }
    
    setScore(finalScore);
    setGameCompleted(true);
    setGameState('completed');
    onGameComplete(finalScore);
  };

  // Start first round when game initializes
  useEffect(() => {
    if (gameState === 'waiting' && !gameCompleted) {
      const timer = setTimeout(() => {
        startRound();
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [gameState, gameCompleted, startRound]);

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };
  }, [timeoutId]);

  const getStateMessage = () => {
    switch (gameState) {
      case 'waiting':
        return 'Get ready...';
      case 'ready':
        return 'Wait for GREEN...';
      case 'go':
        return 'CLICK NOW!';
      case 'clicked':
        return `${reactionTime}ms - Great!`;
      case 'failed':
        return 'Too early! Wait for green.';
      case 'completed':
        return 'Game Complete!';
      default:
        return '';
    }
  };

  const getStateColor = () => {
    switch (gameState) {
      case 'waiting':
        return 'bg-gray-400';
      case 'ready':
        return 'bg-red-500';
      case 'go':
        return 'bg-green-500';
      case 'clicked':
        return 'bg-blue-500';
      case 'failed':
        return 'bg-red-600';
      case 'completed':
        return 'bg-purple-500';
      default:
        return 'bg-gray-400';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-100 p-4">
      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-2xl shadow-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <button
              onClick={onBack}
              className="flex items-center gap-2 px-4 py-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              Back to Games
            </button>
            <button
              onClick={initializeGame}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Restart
            </button>
          </div>
          
          <div className="text-center mb-4">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Reaction Time Test</h1>
            <p className="text-gray-600">Click as fast as you can when the circle turns green!</p>
            <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${
              difficulty === 'easy' ? 'bg-green-100 text-green-800' :
              difficulty === 'medium' ? 'bg-yellow-100 text-yellow-800' :
              'bg-red-100 text-red-800'
            }`}>
              {difficulty.toUpperCase()} - {config.totalRounds} rounds
            </div>
          </div>

          {/* Game Stats */}
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Target className="w-6 h-6 mx-auto mb-1 text-green-600" />
              <p className="text-sm text-gray-600">Round</p>
              <p className="text-lg font-bold text-gray-900">{currentRound}/{config.totalRounds}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Clock className="w-6 h-6 mx-auto mb-1 text-blue-600" />
              <p className="text-sm text-gray-600">Best</p>
              <p className="text-lg font-bold text-gray-900">{bestTime > 0 ? `${bestTime}ms` : '-'}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Zap className="w-6 h-6 mx-auto mb-1 text-orange-600" />
              <p className="text-sm text-gray-600">Average</p>
              <p className="text-lg font-bold text-gray-900">{averageTime > 0 ? `${Math.round(averageTime)}ms` : '-'}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Trophy className="w-6 h-6 mx-auto mb-1 text-yellow-600" />
              <p className="text-sm text-gray-600">Score</p>
              <p className="text-lg font-bold text-gray-900">{score}</p>
            </div>
          </div>
        </div>

        {/* Game Area */}
        <div className="bg-white rounded-2xl shadow-lg p-8">
          <div className="text-center mb-8">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">{getStateMessage()}</h2>
            
            {/* Click Circle */}
            <div 
              onClick={handleClick}
              className={`
                w-64 h-64 mx-auto rounded-full cursor-pointer transition-all duration-200 transform hover:scale-105 active:scale-95
                ${getStateColor()}
                flex items-center justify-center text-white text-2xl font-bold shadow-lg
                ${gameState === 'go' ? 'animate-pulse' : ''}
              `}
            >
              {gameState === 'waiting' && '⏳'}
              {gameState === 'ready' && '🔴'}
              {gameState === 'go' && '🟢'}
              {gameState === 'clicked' && '✅'}
              {gameState === 'failed' && '❌'}
              {gameState === 'completed' && '🏆'}
            </div>
            
            <div className="mt-6">
              {gameState === 'ready' && (
                <p className="text-red-600 font-medium">Don't click yet! Wait for green...</p>
              )}
              {gameState === 'go' && (
                <p className="text-green-600 font-medium animate-bounce">CLICK NOW!</p>
              )}
              {gameState === 'failed' && (
                <p className="text-red-600 font-medium">Too early! Next round starting...</p>
              )}
              {gameState === 'clicked' && (
                <p className="text-blue-600 font-medium">Nice reaction! Next round starting...</p>
              )}
            </div>
          </div>
        </div>

        {/* Round History */}
        {rounds.length > 0 && (
          <div className="bg-white rounded-2xl shadow-lg p-6 mt-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Round History</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {rounds.map((round) => (
                <div key={round.id} className={`p-3 rounded-lg ${
                  round.success ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'
                }`}>
                  <div className="flex items-center justify-between">
                    <span className="font-medium">Round {round.id}</span>
                    <span className={`text-sm ${
                      round.success ? 'text-green-600' : 'text-red-600'
                    }`}>
                      {round.success ? `${round.reactionTime}ms` : 'Too early'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Game Complete Modal */}
        {gameCompleted && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-white rounded-2xl p-8 max-w-md w-full text-center">
              <div className="text-6xl mb-4">⚡</div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Game Complete!</h2>
              <p className="text-gray-600 mb-4">
                You completed the {difficulty} reaction time test!
              </p>
              <div className="bg-gray-50 rounded-lg p-4 mb-6">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600">Best Time</p>
                    <p className="font-bold text-green-600">{bestTime}ms</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Average</p>
                    <p className="font-bold text-blue-600">{Math.round(averageTime)}ms</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Success Rate</p>
                    <p className="font-bold">{Math.round((rounds.filter(r => r.success).length / rounds.length) * 100)}%</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Final Score</p>
                    <p className="font-bold text-purple-600">{score} pts</p>
                  </div>
                </div>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={initializeGame}
                  className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
                >
                  Play Again
                </button>
                <button
                  onClick={onBack}
                  className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                >
                  Back to Games
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ReactionTimeGame;