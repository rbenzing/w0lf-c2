// Register a plugin
module.exports = {
    name: 'Screensavers',
    type: 'server',
    description: 'A server plugin to show a couple screensavers.',
    commands: {
        matrix: {
          name: 'matrix',
          method: 'execute',
          description: 'Shows the matrix style screensaver.',
          handler: (props, { process, rl }) => {
            const width = process.stdout.columns || 80;
            const height = process.stdout.rows || 24;
            const maxActiveRaindrops = 100; // Maximum number of active raindrops
            let animationActive = true; // Flag to control animation state
            const charSet = [
              "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", // English alphabet
              "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", // English alphabet
              "¡", "¿", "ñ", "á", "é", "í", "ó", "ú", "ü", "ß", "ä", "ö", "ë", "ÿ",             // Spanish and Germanic
              "あ", "い", "う", "え", "お", "か", "き", "く", "け", "こ", "さ", "し", "す", "せ", "そ", // Japanese Hiragana
              "ア", "イ", "ウ", "エ", "オ", "カ", "キ", "ク", "ケ", "コ", "サ", "シ", "ス", "セ", "ソ", // Japanese Katakana
              "汉", "字", "漢", "語", "の", "文", "字",                                                  // Chinese characters
              "æ", "ø", "å",                                                                     // Nordic characters
              "ç", "â", "ê", "î", "ô", "û",                                                        // French characters
              "ß", "ä", "ö", "ü",                                                                 // German characters
              "ł", "ą", "ć", "ę", "ń", "ó", "ś", "ź", "ż",                                         // Polish characters
              "ё", "я", "ю", "и", "ж", "э", "щ", "ф", "ы", "в", "у", "т", "р", "е", "й", "о", "п", // Russian Cyrillic
              "θ", "λ", "δ", "ε", "γ", "ρ", "π", "σ", "φ", "χ", "ψ", "ω", "ζ", "η", "κ", "α", "β", // Greek alphabet
              "א", "ב", "ג", "ד", "ה", "ו", "ז", "ח", "ט", "י", "כ", "ל", "מ", "נ", "ס", "ע", "פ", // Hebrew alphabet
              "क", "ख", "ग", "घ", "ङ", "च", "छ", "ज", "झ", "ञ", "ट", "ठ", "ड", "ढ", "ण", "त",     // Devanagari script (Hindi)
              "က", "ခ", "ဂ", "ဃ", "င", "စ", "ဆ", "ဇ", "ဈ", "ဉ", "ည", "ဋ", "ဌ", "ဍ", "ဎ", "ဏ", // Burmese script
              "ក", "ខ", "គ", "ឃ", "ង", "ច", "ឆ", "ជ", "ឈ", "ញ", "ដ", "ឋ", "ឌ", "ឍ", "ណ", "ត", // Khmer script
              "ກ", "ຂ", "ຄ", "ງ", "ຈ", "ສ", "ຫ", "ອ", "ຮ", "ຯ", "ະ", "ັ", "າ", "ຳ", "ິ", "ີ", // Lao script
              "ᄀ", "ᄂ", "ᄃ", "ᄅ", "ᄆ", "ᄇ", "ᄉ", "ᄋ", "ᄌ", "ᄎ", "ᄏ", "ᄐ", "ᄑ", "ᄒ",             // Korean Hangul
              "ཀ", "ཁ", "ག", "ང", "ཆ", "ཇ", "ཉ", "ཊ", "ཋ", "ཌ", "ཎ", "ཏ", "ཐ", "ད", "ན", "པ", // Tibetan script
            ];
          
            const activeRaindrops = [];
          
            // Function to clear the console
            const clearConsole = () => {
              process.stdout.write('\x1b[2J');
            };
          
            // Function to get a random character from charSet
            const getRandomChar = () => charSet[Math.floor(Math.random() * charSet.length)];
          
            // Function to initialize raindrops with random positions and characters
            const initializeRaindrops = () => {
              for (let i = 0; i < Math.min(width, maxActiveRaindrops); i++) {
                const initialChars = Math.floor(Math.random() * 5) + 1; // Random number of initial characters
                activeRaindrops.push({
                  x: Math.floor(Math.random() * width), // Random initial x position across width
                  y: -Math.floor(Math.random() * height), // Random initial y position above screen
                  chars: Array.from({ length: initialChars }, () => getRandomChar()),
                  speed: Math.random() * 0.5 + 0.2, // Random speed between 0.2 and 0.7
                });
              }
            };
          
            // Function to update raindrops positions and redraw them
            const updateRaindrops = () => {
              let output = '';
          
              activeRaindrops.forEach((drop, index) => {
                // Erase previous raindrop
                drop.chars.forEach((char, charIndex) => {
                  const prevY = Math.floor(drop.y) - charIndex;
                  if (prevY >= 0 && prevY < height) {
                    output += `\x1b[${prevY + 1};${drop.x + 1}H `; // Clear previous position
                  }
                });
          
                // Update raindrop position
                drop.y += drop.speed;
          
                // Clear out-of-screen raindrops and reuse them
                if (drop.y >= height) {
                  const newChars = Math.floor(Math.random() * 5) + 1; // Random number of new characters
                  drop.y = -Math.floor(Math.random() * height); // Reset y position above screen
                  drop.chars = Array.from({ length: newChars }, () => getRandomChar()); // Reset characters
                  drop.speed = Math.random() * 0.5 + 0.2; // Reset speed
                  drop.x = Math.floor(Math.random() * width); // Randomize x position across width
                }
          
                // Draw raindrop at new position within visible area
                drop.chars.forEach((char, charIndex) => {
                  const newY = Math.floor(drop.y) - charIndex;
                  if (newY >= 0 && newY < height) {
                    output += `\x1b[${newY + 1};${drop.x + 1}H\x1b[32m${char}\x1b[0m`; // Lime green color
                  }
                });
              });
          
              process.stdout.write(output);
            };
          
            // Main animation loop
            const animate = () => {
              if (!animationActive) return; // Stop animation if not active
              clearConsole();
              updateRaindrops();
              setTimeout(animate, 50); // Adjust animation speed here
            };
          
            // Start animation
            initializeRaindrops();
            animate();
          
            // Handle keypress to exit animation
            rl.input.on('keypress', (_, key) => {
              if (key.name === 'return') {
                animationActive = false;
                rl.prompt();
              }
            });
          }                                                                                                                                                                                                                        
        },
        fire: {
            name: 'fire',
            method: 'execute',
            description: 'Shows a fire screensaver.',
            handler: (props, { process, rl }) => {
              const width = process.stdout.columns || 80;
              const height = process.stdout.rows || 24;
              const size = width * height;
              const chars = [" ", ".", ":", "^", "*", "x", "s", "S", "#", "$"];
              let b = new Uint8Array(size + width + 1);
              let lastLines = new Array(height).fill('');
              let animationActive = true; // Flag to control animation state
            
              // Function to clear the console
              const clearConsole = () => {
                process.stdout.write('\x1b[2J');
              };
            
              // Function to move cursor position using ANSI escape codes
              const moveTo = (x, y) => {
                process.stdout.write(`\x1b[${y};${x}H`);
              };
            
              // Initialize ANSI color codes
              const colors = {
                1: '37',  // white
                2: '31',  // red
                3: '33',  // yellow
                4: '36'   // cyan
              };
            
              // Main animation loop
              const animate = () => {
                if (!animationActive) return; // Stop animation if not active
          
                // Generate sparks randomly
                for (let i = 0; i < width / 9; i++) {
                  b[Math.floor(Math.random() * width) + width * (height - 1)] = 65;
                }
            
                // Update fire simulation
                let output = '';
                for (let y = 0; y < height; y++) {
                  let line = '';
                  for (let x = 0; x < width; x++) {
                    const index = y * width + x;
                    b[index] = Math.floor((b[index] + b[index + 1] + b[index + width] + b[index + width + 1]) / 4);
                    const color = (b[index] > 15 ? 4 : (b[index] > 9 ? 3 : (b[index] > 4 ? 2 : 1)));
                    const charIndex = (b[index] > 9 ? 9 : b[index]);
                    line += `\x1b[${colors[color]}m${chars[charIndex]}`;
                  }
                  if (line !== lastLines[y]) {
                    output += `\x1b[${y + 1};1H${line}`;
                    lastLines[y] = line;
                  }
                }
            
                // Output all changes at once
                moveTo(1, 1);
                process.stdout.write(output);
            
                // Repeat animation
                setTimeout(animate, 30);
              };
            
              // Start animation
              const startAnimation = () => {
                clearConsole();
                animate();
              };
          
              // Stop animation and show readline prompt
              const stopAnimation = () => {
                  animationActive = false;
                  rl.prompt();
              };
          
              rl.input.on('keypress', (_, key) => {
                  if (key.name === 'return') {
                    stopAnimation();
                  }
              });
            
              // Initialize animation
              startAnimation();
            }
        }
    }
};