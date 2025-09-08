import React, { useState, useEffect, useCallback } from 'react';
import { ArrowLeft, RotateCcw, Trophy, Clock, Shuffle, CheckCircle, XCircle } from 'lucide-react';

interface WordScrambleGameProps {
  onBack: () => void;
  onGameComplete: (score: number) => void;
  difficulty: 'easy' | 'medium' | 'hard';
}

interface Word {
  original: string;
  scrambled: string;
  hint: string;
}

interface Round {
  id: number;
  word: string;
  guess: string;
  correct: boolean;
  timeUsed: number;
}

type GameState = 'playing' | 'completed' | 'paused';

const WordScrambleGame: React.FC<WordScrambleGameProps> = ({ onBack, onGameComplete, difficulty }) => {
  const [gameState, setGameState] = useState<GameState>('playing');
  const [currentWordIndex, setCurrentWordIndex] = useState(0);
  const [currentGuess, setCurrentGuess] = useState('');
  const [rounds, setRounds] = useState<Round[]>([]);
  const [score, setScore] = useState(0);
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [roundStartTime, setRoundStartTime] = useState(Date.now());
  const [gameCompleted, setGameCompleted] = useState(false);
  const [showHint, setShowHint] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'correct' | 'incorrect' | null; message: string }>({ type: null, message: '' });

  // Word lists based on difficulty
  const getWordList = (): Word[] => {
    switch (difficulty) {
      case 'easy':
        return [
          { original: 'CAR', scrambled: 'RAC', hint: 'Vehicle for transportation' },
          { original: 'TAXI', scrambled: 'ITAX', hint: 'Yellow cab service' },
          { original: 'ROAD', scrambled: 'DARO', hint: 'Path for vehicles' },
          { original: 'TRIP', scrambled: 'PRIT', hint: 'A journey' },
          { original: 'RIDE', scrambled: 'EDIR', hint: 'To travel in a vehicle' },
          { original: 'CITY', scrambled: 'YITC', hint: 'Urban area' },
          { original: 'BOOK', scrambled: 'KOOB', hint: 'To reserve or schedule' },
          { original: 'FAST', scrambled: 'TSAF', hint: 'Quick speed' }
        ];
      case 'medium':
        return [
          { original: 'DRIVER', scrambled: 'REVIRD', hint: 'Person who operates a vehicle' },
          { original: 'BOOKING', scrambled: 'GNIKBOO', hint: 'Making a reservation' },
          { original: 'JOURNEY', scrambled: 'YENRUOJ', hint: 'A trip from one place to another' },
          { original: 'TRAFFIC', scrambled: 'CIFFARR', hint: 'Vehicles on the road' },
          { original: 'AIRPORT', scrambled: 'TROPRIA', hint: 'Place where planes land' },
          { original: 'STATION', scrambled: 'NOITATSS', hint: 'Transportation hub' },
          { original: 'PAYMENT', scrambled: 'TNEMYAP', hint: 'Money for services' },
          { original: 'ARRIVAL', scrambled: 'LAVIRA', hint: 'Reaching destination' },
          { original: 'PICKUP', scrambled: 'PUKCIP', hint: 'Collection point' },
          { original: 'ROUTE', scrambled: 'ETUOR', hint: 'Path to destination' }
        ];
      case 'hard':
        return [
          { original: 'TRANSPORTATION', scrambled: 'NOITATROPSNART', hint: 'Moving people or goods' },
          { original: 'DESTINATION', scrambled: 'NOITANITSED', hint: 'Final stopping place' },
          { original: 'NAVIGATION', scrambled: 'NOITAGIVAN', hint: 'Finding your way' },
          { original: 'PASSENGER', scrambled: 'REGNESSSAP', hint: 'Person being transported' },
          { original: 'SCHEDULE', scrambled: 'ELUDEHCS', hint: 'Planned timetable' },
          { original: 'LOCATION', scrambled: 'NOITACOL', hint: 'Specific place or position' },
          { original: 'DISTANCE', scrambled: 'ECNATSID', hint: 'Space between two points' },
          { original: 'VEHICLE', scrambled: 'ELCIHEV', hint: 'Means of transport' },
          { original: 'ESTIMATE', scrambled: 'ETAMITSE', hint: 'Approximate calculation' },
          { original: 'CONFIRMATION', scrambled: 'NOITAMRIFNOC', hint: 'Verification of booking' },
          { original: 'METROPOLITAN', scrambled: 'NATILOPORTEM', hint: 'Related to a large city' },
          { original: 'COORDINATES', scrambled: 'SETANIDROOC', hint: 'Geographic position data' }
        ];
      default:
        return [];
    }
  };

  const [words] = useState<Word[]>(getWordList());
  const [currentWord, setCurrentWord] = useState<Word>(words[0]);

  // Game configuration
  const getGameConfig = () => {
    switch (difficulty) {
      case 'easy': 
        return { 
          baseScore: 100,
          timeBonus: 50,
          hintPenalty: 20,
          maxTime: 60
        };
      case 'medium': 
        return { 
          baseScore: 150,
          timeBonus: 75,
          hintPenalty: 30,
          maxTime: 90
        };
      case 'hard': 
        return { 
          baseScore: 200,
          timeBonus: 100,
          hintPenalty: 40,
          maxTime: 120
        };
      default: 
        return { 
          baseScore: 100,
          timeBonus: 50,
          hintPenalty: 20,
          maxTime: 60
        };
    }
  };

  const config = getGameConfig();

  // Scramble a word
  const scrambleWord = (word: string): string => {
    const letters = word.split('');
    for (let i = letters.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [letters[i], letters[j]] = [letters[j], letters[i]];
    }
    return letters.join('');
  };

  // Initialize game
  const initializeGame = () => {
    setGameState('playing');
    setCurrentWordIndex(0);
    setCurrentGuess('');
    setRounds([]);
    setScore(0);
    setTimeElapsed(0);
    setRoundStartTime(Date.now());
    setGameCompleted(false);
    setShowHint(false);
    setFeedback({ type: null, message: '' });
    
    // Set first word with new scramble
    const firstWord = words[0];
    setCurrentWord({
      ...firstWord,
      scrambled: scrambleWord(firstWord.original)
    });
  };

  // Handle guess submission
  const handleGuess = useCallback(() => {
    if (!currentGuess.trim() || gameCompleted) return;
    
    const timeUsed = Math.floor((Date.now() - roundStartTime) / 1000);
    const isCorrect = currentGuess.toUpperCase() === currentWord.original.toUpperCase();
    
    const newRound: Round = {
      id: currentWordIndex + 1,
      word: currentWord.original,
      guess: currentGuess,
      correct: isCorrect,
      timeUsed
    };
    
    setRounds(prev => [...prev, newRound]);
    
    if (isCorrect) {
      // Calculate score
      let roundScore = config.baseScore;
      const timeBonus = Math.max(0, config.timeBonus - timeUsed * 2);
      roundScore += timeBonus;
      if (showHint) {
        roundScore -= config.hintPenalty;
      }
      
      setScore(prev => prev + roundScore);
      setFeedback({ 
        type: 'correct', 
        message: `Correct! +${roundScore} points${showHint ? ` (-${config.hintPenalty} for hint)` : ''}` 
      });
    } else {
      setFeedback({ 
        type: 'incorrect', 
        message: `Incorrect! The word was "${currentWord.original}"` 
      });
    }
    
    // Move to next word or complete game
    setTimeout(() => {
      if (currentWordIndex + 1 >= words.length) {
        completeGame([...rounds, newRound]);
      } else {
        setCurrentWordIndex(prev => prev + 1);
        const nextWord = words[currentWordIndex + 1];
        setCurrentWord({
          ...nextWord,
          scrambled: scrambleWord(nextWord.original)
        });
        setCurrentGuess('');
        setShowHint(false);
        setRoundStartTime(Date.now());
        setFeedback({ type: null, message: '' });
      }
    }, 2000);
  }, [currentGuess, currentWord, currentWordIndex, words, rounds, config, showHint, roundStartTime, gameCompleted]);

  // Complete the game
  const completeGame = (finalRounds: Round[]) => {
    const correctAnswers = finalRounds.filter(r => r.correct).length;
    const totalTime = finalRounds.reduce((sum, r) => sum + r.timeUsed, 0);
    
    // Bonus for completion rate
    const completionBonus = Math.floor((correctAnswers / finalRounds.length) * 500);
    setScore(prev => prev + completionBonus);
    
    setGameCompleted(true);
    setGameState('completed');
    onGameComplete(score + completionBonus);
  };

  // Handle key press
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleGuess();
    }
  };

  // Timer effect
  useEffect(() => {
    if (gameState === 'playing' && !gameCompleted) {
      const timer = setInterval(() => {
        setTimeElapsed(prev => prev + 1);
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [gameState, gameCompleted]);

  // Initialize game on mount
  useEffect(() => {
    initializeGame();
  }, []);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getAccuracy = () => {
    if (rounds.length === 0) return 0;
    return Math.round((rounds.filter(r => r.correct).length / rounds.length) * 100);
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
              Restart
            </button>
          </div>
          
          <div className="text-center mb-4">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Word Scramble</h1>
            <p className="text-gray-600">Unscramble the letters to form the correct word!</p>
            <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${
              difficulty === 'easy' ? 'bg-green-100 text-green-800' :
              difficulty === 'medium' ? 'bg-yellow-100 text-yellow-800' :
              'bg-red-100 text-red-800'
            }`}>
              {difficulty.toUpperCase()} - {words.length} words
            </div>
          </div>

          {/* Game Stats */}
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Shuffle className="w-6 h-6 mx-auto mb-1 text-purple-600" />
              <p className="text-sm text-gray-600">Word</p>
              <p className="text-lg font-bold text-gray-900">{currentWordIndex + 1}/{words.length}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Clock className="w-6 h-6 mx-auto mb-1 text-blue-600" />
              <p className="text-sm text-gray-600">Time</p>
              <p className="text-lg font-bold text-gray-900">{formatTime(timeElapsed)}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <CheckCircle className="w-6 h-6 mx-auto mb-1 text-green-600" />
              <p className="text-sm text-gray-600">Accuracy</p>
              <p className="text-lg font-bold text-gray-900">{getAccuracy()}%</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Trophy className="w-6 h-6 mx-auto mb-1 text-yellow-600" />
              <p className="text-sm text-gray-600">Score</p>
              <p className="text-lg font-bold text-gray-900">{score}</p>
            </div>
          </div>
        </div>

        {/* Game Area */}
        {!gameCompleted && (
          <div className="bg-white rounded-2xl shadow-lg p-8">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-gray-900 mb-4">Unscramble this word:</h2>
              
              {/* Scrambled Word */}
              <div className="bg-purple-100 rounded-2xl p-8 mb-6">
                <div className="text-4xl font-bold text-purple-800 tracking-widest mb-4">
                  {currentWord.scrambled}
                </div>
                <div className="text-sm text-purple-600">
                  {currentWord.original.length} letters
                </div>
              </div>
              
              {/* Hint Section */}
              <div className="mb-6">
                {!showHint ? (
                  <button
                    onClick={() => setShowHint(true)}
                    className="px-4 py-2 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600 transition-colors"
                  >
                    Show Hint (-{config.hintPenalty} points)
                  </button>
                ) : (
                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                    <p className="text-yellow-800 font-medium">💡 Hint: {currentWord.hint}</p>
                  </div>
                )}
              </div>
              
              {/* Input */}
              <div className="mb-6">
                <input
                  type="text"
                  value={currentGuess}
                  onChange={(e) => setCurrentGuess(e.target.value.toUpperCase())}
                  onKeyPress={handleKeyPress}
                  placeholder="Enter your guess..."
                  className="w-full max-w-md px-4 py-3 text-xl text-center border-2 border-gray-300 rounded-lg focus:border-purple-500 focus:outline-none"
                  disabled={feedback.type !== null}
                />
              </div>
              
              {/* Submit Button */}
              <button
                onClick={handleGuess}
                disabled={!currentGuess.trim() || feedback.type !== null}
                className="px-8 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors font-medium"
              >
                Submit Guess
              </button>
              
              {/* Feedback */}
              {feedback.type && (
                <div className={`mt-4 p-4 rounded-lg ${
                  feedback.type === 'correct' ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'
                }`}>
                  <div className="flex items-center justify-center gap-2">
                    {feedback.type === 'correct' ? (
                      <CheckCircle className="w-5 h-5 text-green-600" />
                    ) : (
                      <XCircle className="w-5 h-5 text-red-600" />
                    )}
                    <p className={`font-medium ${
                      feedback.type === 'correct' ? 'text-green-800' : 'text-red-800'
                    }`}>
                      {feedback.message}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Progress */}
        {rounds.length > 0 && (
          <div className="bg-white rounded-2xl shadow-lg p-6 mt-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Progress</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {rounds.map((round) => (
                <div key={round.id} className={`p-3 rounded-lg ${
                  round.correct ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'
                }`}>
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-medium">{round.word}</span>
                      <p className="text-sm text-gray-600">Guess: {round.guess}</p>
                    </div>
                    <div className="text-right">
                      <span className={`text-sm ${
                        round.correct ? 'text-green-600' : 'text-red-600'
                      }`}>
                        {round.correct ? '✓' : '✗'}
                      </span>
                      <p className="text-xs text-gray-500">{round.timeUsed}s</p>
                    </div>
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
              <div className="text-6xl mb-4">🎯</div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Game Complete!</h2>
              <p className="text-gray-600 mb-4">
                You completed the {difficulty} word scramble!
              </p>
              <div className="bg-gray-50 rounded-lg p-4 mb-6">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600">Correct</p>
                    <p className="font-bold text-green-600">{rounds.filter(r => r.correct).length}/{rounds.length}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Accuracy</p>
                    <p className="font-bold text-blue-600">{getAccuracy()}%</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Total Time</p>
                    <p className="font-bold">{formatTime(timeElapsed)}</p>
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

export default WordScrambleGame;