import React, { useState, useEffect } from 'react';
import { ArrowLeft, RotateCcw, Trophy, Target, Zap, TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface NumberGuessingGameProps {
  onBack: () => void;
  onGameComplete: (score: number) => void;
  difficulty: 'easy' | 'medium' | 'hard';
}

const NumberGuessingGame: React.FC<NumberGuessingGameProps> = ({ onBack, onGameComplete, difficulty }) => {
  const [targetNumber, setTargetNumber] = useState(0);
  const [guess, setGuess] = useState('');
  const [attempts, setAttempts] = useState(0);
  const [maxAttempts, setMaxAttempts] = useState(0);
  const [feedback, setFeedback] = useState('');
  const [gameCompleted, setGameCompleted] = useState(false);
  const [gameWon, setGameWon] = useState(false);
  const [score, setScore] = useState(0);
  const [guessHistory, setGuessHistory] = useState<{guess: number, feedback: string}[]>([]);
  const [range, setRange] = useState({ min: 1, max: 100 });
  const [hint, setHint] = useState('');

  // Game configuration based on difficulty
  const getGameConfig = () => {
    switch (difficulty) {
      case 'easy': 
        return { 
          min: 1, 
          max: 50, 
          maxAttempts: 8, 
          baseScore: 100,
          hintAfter: 4
        };
      case 'medium': 
        return { 
          min: 1, 
          max: 100, 
          maxAttempts: 7, 
          baseScore: 200,
          hintAfter: 3
        };
      case 'hard': 
        return { 
          min: 1, 
          max: 200, 
          maxAttempts: 6, 
          baseScore: 300,
          hintAfter: 2
        };
      default: 
        return { 
          min: 1, 
          max: 50, 
          maxAttempts: 8, 
          baseScore: 100,
          hintAfter: 4
        };
    }
  };

  const config = getGameConfig();

  // Initialize game
  const initializeGame = () => {
    const newTarget = Math.floor(Math.random() * (config.max - config.min + 1)) + config.min;
    setTargetNumber(newTarget);
    setGuess('');
    setAttempts(0);
    setMaxAttempts(config.maxAttempts);
    setFeedback('');
    setGameCompleted(false);
    setGameWon(false);
    setScore(0);
    setGuessHistory([]);
    setRange({ min: config.min, max: config.max });
    setHint('');
  };

  // Handle guess submission
  const handleGuess = () => {
    const guessNumber = parseInt(guess);
    
    if (isNaN(guessNumber) || guessNumber < config.min || guessNumber > config.max) {
      setFeedback(`Please enter a number between ${config.min} and ${config.max}`);
      return;
    }

    const newAttempts = attempts + 1;
    setAttempts(newAttempts);
    
    let newFeedback = '';
    let newRange = { ...range };
    
    if (guessNumber === targetNumber) {
      // Correct guess!
      newFeedback = '🎉 Correct! You found the number!';
      setGameWon(true);
      setGameCompleted(true);
      
      // Calculate score based on attempts
      const attemptBonus = Math.max(0, (config.maxAttempts - newAttempts) * 20);
      const finalScore = config.baseScore + attemptBonus;
      setScore(finalScore);
      onGameComplete(finalScore);
    } else if (guessNumber < targetNumber) {
      newFeedback = '📈 Too low! Try a higher number.';
      newRange.min = Math.max(newRange.min, guessNumber + 1);
    } else {
      newFeedback = '📉 Too high! Try a lower number.';
      newRange.max = Math.min(newRange.max, guessNumber - 1);
    }
    
    setFeedback(newFeedback);
    setRange(newRange);
    setGuessHistory(prev => [...prev, { guess: guessNumber, feedback: newFeedback }]);
    
    // Check if game is over (max attempts reached)
    if (newAttempts >= config.maxAttempts && guessNumber !== targetNumber) {
      setGameCompleted(true);
      setGameWon(false);
      setFeedback(`💔 Game Over! The number was ${targetNumber}`);
      onGameComplete(0);
    }
    
    // Provide hint after certain attempts
    if (newAttempts === config.hintAfter && guessNumber !== targetNumber) {
      const isEven = targetNumber % 2 === 0;
      const divisibleBy3 = targetNumber % 3 === 0;
      const divisibleBy5 = targetNumber % 5 === 0;
      
      let hintText = `💡 Hint: The number is ${isEven ? 'even' : 'odd'}`;
      if (divisibleBy3) hintText += ' and divisible by 3';
      if (divisibleBy5) hintText += ' and divisible by 5';
      
      setHint(hintText);
    }
    
    setGuess('');
  };

  // Handle Enter key press
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !gameCompleted) {
      handleGuess();
    }
  };

  // Initialize game on mount
  useEffect(() => {
    initializeGame();
  }, [difficulty]);

  const getFeedbackIcon = (feedback: string) => {
    if (feedback.includes('Too low')) return <TrendingUp className="w-4 h-4 text-red-500" />;
    if (feedback.includes('Too high')) return <TrendingDown className="w-4 h-4 text-blue-500" />;
    if (feedback.includes('Correct')) return <Trophy className="w-4 h-4 text-green-500" />;
    return <Minus className="w-4 h-4 text-gray-500" />;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 to-pink-100 p-4">
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
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              New Game
            </button>
          </div>
          
          <div className="text-center mb-4">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Number Guessing Game</h1>
            <p className="text-gray-600">I'm thinking of a number between {config.min} and {config.max}</p>
            <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${
              difficulty === 'easy' ? 'bg-green-100 text-green-800' :
              difficulty === 'medium' ? 'bg-yellow-100 text-yellow-800' :
              'bg-red-100 text-red-800'
            }`}>
              {difficulty.toUpperCase()} - {config.maxAttempts} attempts
            </div>
          </div>

          {/* Game Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Target className="w-6 h-6 mx-auto mb-1 text-purple-600" />
              <p className="text-sm text-gray-600">Attempts</p>
              <p className="text-lg font-bold text-gray-900">{attempts}/{maxAttempts}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Zap className="w-6 h-6 mx-auto mb-1 text-orange-600" />
              <p className="text-sm text-gray-600">Range</p>
              <p className="text-lg font-bold text-gray-900">{range.min}-{range.max}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Trophy className="w-6 h-6 mx-auto mb-1 text-yellow-600" />
              <p className="text-sm text-gray-600">Score</p>
              <p className="text-lg font-bold text-gray-900">{score}</p>
            </div>
          </div>
        </div>

        {/* Game Input */}
        <div className="bg-white rounded-2xl shadow-lg p-6 mb-6">
          <div className="text-center mb-6">
            <label className="block text-lg font-medium text-gray-700 mb-4">
              Enter your guess:
            </label>
            <div className="flex gap-3 max-w-xs mx-auto">
              <input
                type="number"
                value={guess}
                onChange={(e) => setGuess(e.target.value)}
                onKeyPress={handleKeyPress}
                min={range.min}
                max={range.max}
                disabled={gameCompleted}
                className="flex-1 px-4 py-3 text-xl text-center border-2 border-gray-300 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 disabled:bg-gray-100"
                placeholder="?"
              />
              <button
                onClick={handleGuess}
                disabled={gameCompleted || !guess}
                className="px-6 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors font-medium"
              >
                Guess
              </button>
            </div>
          </div>

          {/* Feedback */}
          {feedback && (
            <div className={`text-center p-4 rounded-lg mb-4 ${
              feedback.includes('Correct') ? 'bg-green-100 text-green-800' :
              feedback.includes('Game Over') ? 'bg-red-100 text-red-800' :
              'bg-blue-100 text-blue-800'
            }`}>
              <p className="text-lg font-medium">{feedback}</p>
            </div>
          )}

          {/* Hint */}
          {hint && (
            <div className="text-center p-3 bg-yellow-100 text-yellow-800 rounded-lg mb-4">
              <p className="font-medium">{hint}</p>
            </div>
          )}
        </div>

        {/* Guess History */}
        {guessHistory.length > 0 && (
          <div className="bg-white rounded-2xl shadow-lg p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Guess History</h3>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {guessHistory.map((entry, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <span className="w-8 h-8 bg-purple-100 text-purple-800 rounded-full flex items-center justify-center text-sm font-bold">
                      {index + 1}
                    </span>
                    <span className="text-lg font-medium">{entry.guess}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-600">
                    {getFeedbackIcon(entry.feedback)}
                    <span>{entry.feedback.replace(/[📈📉🎉💔]/g, '').trim()}</span>
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
              <div className="text-6xl mb-4">
                {gameWon ? '🎉' : '💔'}
              </div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">
                {gameWon ? 'Congratulations!' : 'Game Over!'}
              </h2>
              <p className="text-gray-600 mb-4">
                {gameWon 
                  ? `You guessed the number ${targetNumber} in ${attempts} attempts!`
                  : `The number was ${targetNumber}. Better luck next time!`
                }
              </p>
              <div className="bg-gray-50 rounded-lg p-4 mb-6">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600">Attempts</p>
                    <p className="font-bold">{attempts}/{maxAttempts}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Difficulty</p>
                    <p className="font-bold capitalize">{difficulty}</p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-gray-600">Final Score</p>
                    <p className="font-bold text-purple-600 text-xl">{score} pts</p>
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
                  className="flex-1 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
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

export default NumberGuessingGame;