import React, { useState, useEffect } from 'react';
import { ArrowLeft, RotateCcw, Trophy, Clock, Target } from 'lucide-react';

interface Card {
  id: number;
  value: string;
  isFlipped: boolean;
  isMatched: boolean;
}

interface MemoryGameProps {
  onBack: () => void;
  onGameComplete: (score: number) => void;
  difficulty: 'easy' | 'medium' | 'hard';
}

const MemoryGame: React.FC<MemoryGameProps> = ({ onBack, onGameComplete, difficulty }) => {
  const [cards, setCards] = useState<Card[]>([]);
  const [flippedCards, setFlippedCards] = useState<number[]>([]);
  const [matchedPairs, setMatchedPairs] = useState(0);
  const [moves, setMoves] = useState(0);
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [gameStarted, setGameStarted] = useState(false);
  const [gameCompleted, setGameCompleted] = useState(false);
  const [score, setScore] = useState(0);

  // Game configuration based on difficulty
  const getGameConfig = () => {
    switch (difficulty) {
      case 'easy': return { pairs: 6, timeBonus: 300, maxTime: 120 };
      case 'medium': return { pairs: 8, timeBonus: 400, maxTime: 180 };
      case 'hard': return { pairs: 12, timeBonus: 500, maxTime: 240 };
      default: return { pairs: 6, timeBonus: 300, maxTime: 120 };
    }
  };

  const config = getGameConfig();
  const totalPairs = config.pairs;

  // Card symbols for the memory game
  const symbols = ['🚗', '🚕', '🚙', '🚌', '🚎', '🏎️', '🚓', '🚑', '🚒', '🚐', '🛻', '🚚', '🚛', '🏍️', '🛵', '🚲'];

  // Initialize game
  const initializeGame = () => {
    const gameSymbols = symbols.slice(0, totalPairs);
    const cardPairs = [...gameSymbols, ...gameSymbols];
    
    // Shuffle cards
    const shuffledCards = cardPairs
      .map((symbol, index) => ({
        id: index,
        value: symbol,
        isFlipped: false,
        isMatched: false
      }))
      .sort(() => Math.random() - 0.5);

    setCards(shuffledCards);
    setFlippedCards([]);
    setMatchedPairs(0);
    setMoves(0);
    setTimeElapsed(0);
    setGameStarted(false);
    setGameCompleted(false);
    setScore(0);
  };

  // Timer effect
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (gameStarted && !gameCompleted) {
      interval = setInterval(() => {
        setTimeElapsed(prev => {
          if (prev >= config.maxTime) {
            // Time's up - end game
            setGameCompleted(true);
            const finalScore = Math.max(0, matchedPairs * 50 - moves * 2);
            setScore(finalScore);
            onGameComplete(finalScore);
            return prev;
          }
          return prev + 1;
        });
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [gameStarted, gameCompleted, matchedPairs, moves, config.maxTime, onGameComplete]);

  // Handle card click
  const handleCardClick = (cardId: number) => {
    if (!gameStarted) {
      setGameStarted(true);
    }

    if (flippedCards.length === 2 || gameCompleted) return;
    
    const card = cards.find(c => c.id === cardId);
    if (!card || card.isFlipped || card.isMatched) return;

    const newFlippedCards = [...flippedCards, cardId];
    setFlippedCards(newFlippedCards);

    // Update card state
    setCards(prev => prev.map(c => 
      c.id === cardId ? { ...c, isFlipped: true } : c
    ));

    // Check for match when two cards are flipped
    if (newFlippedCards.length === 2) {
      setMoves(prev => prev + 1);
      
      const [firstId, secondId] = newFlippedCards;
      const firstCard = cards.find(c => c.id === firstId);
      const secondCard = cards.find(c => c.id === secondId);

      if (firstCard && secondCard && firstCard.value === secondCard.value) {
        // Match found
        setTimeout(() => {
          setCards(prev => prev.map(c => 
            c.id === firstId || c.id === secondId 
              ? { ...c, isMatched: true }
              : c
          ));
          setMatchedPairs(prev => {
            const newMatched = prev + 1;
            // Check if game is complete
            if (newMatched === totalPairs) {
              setGameCompleted(true);
              const timeBonus = Math.max(0, config.timeBonus - timeElapsed * 2);
              const movesPenalty = moves * 2;
              const finalScore = Math.max(0, newMatched * 100 + timeBonus - movesPenalty);
              setScore(finalScore);
              onGameComplete(finalScore);
            }
            return newMatched;
          });
          setFlippedCards([]);
        }, 500);
      } else {
        // No match - flip cards back
        setTimeout(() => {
          setCards(prev => prev.map(c => 
            c.id === firstId || c.id === secondId 
              ? { ...c, isFlipped: false }
              : c
          ));
          setFlippedCards([]);
        }, 1000);
      }
    }
  };

  // Initialize game on mount
  useEffect(() => {
    initializeGame();
  }, [difficulty]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getGridCols = () => {
    switch (difficulty) {
      case 'easy': return 'grid-cols-4';
      case 'medium': return 'grid-cols-4';
      case 'hard': return 'grid-cols-6';
      default: return 'grid-cols-4';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
      <div className="max-w-4xl mx-auto">
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
            <div className="flex items-center gap-4">
              <button
                onClick={initializeGame}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <RotateCcw className="w-4 h-4" />
                Reset
              </button>
            </div>
          </div>
          
          <div className="text-center mb-4">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Memory Card Game</h1>
            <p className="text-gray-600">Match all the vehicle pairs to win!</p>
            <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${
              difficulty === 'easy' ? 'bg-green-100 text-green-800' :
              difficulty === 'medium' ? 'bg-yellow-100 text-yellow-800' :
              'bg-red-100 text-red-800'
            }`}>
              {difficulty.toUpperCase()} - {totalPairs} pairs
            </div>
          </div>

          {/* Game Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Clock className="w-6 h-6 mx-auto mb-1 text-blue-600" />
              <p className="text-sm text-gray-600">Time</p>
              <p className="text-lg font-bold text-gray-900">{formatTime(timeElapsed)}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Target className="w-6 h-6 mx-auto mb-1 text-green-600" />
              <p className="text-sm text-gray-600">Moves</p>
              <p className="text-lg font-bold text-gray-900">{moves}</p>
            </div>
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <Trophy className="w-6 h-6 mx-auto mb-1 text-yellow-600" />
              <p className="text-sm text-gray-600">Pairs Found</p>
              <p className="text-lg font-bold text-gray-900">{matchedPairs}/{totalPairs}</p>
            </div>
          </div>
        </div>

        {/* Game Board */}
        <div className="bg-white rounded-2xl shadow-lg p-6">
          <div className={`grid ${getGridCols()} gap-4 max-w-2xl mx-auto`}>
            {cards.map((card) => (
              <div
                key={card.id}
                onClick={() => handleCardClick(card.id)}
                className={`
                  aspect-square rounded-xl cursor-pointer transition-all duration-300 transform hover:scale-105
                  ${
                    card.isFlipped || card.isMatched
                      ? 'bg-white border-2 border-blue-300 shadow-lg'
                      : 'bg-gradient-to-br from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 shadow-md'
                  }
                  ${
                    card.isMatched
                      ? 'ring-4 ring-green-300 bg-green-50'
                      : ''
                  }
                `}
              >
                <div className="w-full h-full flex items-center justify-center">
                  {card.isFlipped || card.isMatched ? (
                    <span className="text-4xl">{card.value}</span>
                  ) : (
                    <div className="w-8 h-8 bg-white/20 rounded-lg"></div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Game Complete Modal */}
        {gameCompleted && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-white rounded-2xl p-8 max-w-md w-full text-center">
              <div className="text-6xl mb-4">
                {matchedPairs === totalPairs ? '🎉' : '⏰'}
              </div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">
                {matchedPairs === totalPairs ? 'Congratulations!' : 'Time\'s Up!'}
              </h2>
              <p className="text-gray-600 mb-4">
                {matchedPairs === totalPairs 
                  ? `You completed the ${difficulty} level!`
                  : `You found ${matchedPairs} out of ${totalPairs} pairs.`
                }
              </p>
              <div className="bg-gray-50 rounded-lg p-4 mb-6">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600">Time</p>
                    <p className="font-bold">{formatTime(timeElapsed)}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Moves</p>
                    <p className="font-bold">{moves}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Pairs</p>
                    <p className="font-bold">{matchedPairs}/{totalPairs}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Score</p>
                    <p className="font-bold text-blue-600">{score} pts</p>
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
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
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

export default MemoryGame;