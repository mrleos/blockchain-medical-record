const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse URL-encoded data and serve static files
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// ----------------------------
// Manual SHA-256 Implementation
// ----------------------------

function sha256(ascii) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var lengthProperty = 'length';
    var i, j;
    var result = '';

    // Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    var hash = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    // Initialize array of round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
    var k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    // Pre-processing (Padding)
    ascii += '\x80'; // Append the "1" bit (plus zero padding)
    while ((ascii[lengthProperty] % 64) !== 56) {
        ascii += '\x00';
    }
    var asciiBitLength = ascii[lengthProperty] * 8;
    for (i = 0; i < 8; i++) {
        ascii += String.fromCharCode((asciiBitLength >>> ((7 - i) * 8)) & 0xff);
    }

    // Convert string into an array of 32-bit words
    var words = [];
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = i >> 2;
        words[j] = (words[j] || 0) | (ascii.charCodeAt(i) << ((3 - (i % 4)) * 8));
    }

    // Process the message in successive 512-bit chunks:
    for (j = 0; j < words[lengthProperty]; j += 16) {
        var w = words.slice(j, j + 16);
        var oldHash = hash.slice(0);

        // Extend the 16-word chunk into 64 words
        for (i = 16; i < 64; i++) {
            var s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            var s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }

        // Main loop:
        for (i = 0; i < 64; i++) {
            var s1 = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
            var ch = (hash[4] & hash[5]) ^ ((~hash[4]) & hash[6]);
            var temp1 = (hash[7] + s1 + ch + k[i] + w[i]) | 0;
            var s0 = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
            var maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
            var temp2 = (s0 + maj) | 0;

            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
            hash.pop();
        }

        // Add this chunk's hash to result so far:
        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }

    // Produce the final hash value as a hex string.
    for (i = 0; i < hash[lengthProperty]; i++) {
        for (j = 3; j >= 0; j--) {
            var b = (hash[i] >> (j * 8)) & 0xff;
            result += ((b < 16) ? "0" : "") + b.toString(16);
        }
    }
    return result;
}

// ----------------------------
// Blockchain Classes
// ----------------------------

// Block class for each block in the chain.
class Block {
    constructor(index, timestamp, data, previousHash = "") {
        this.index = index;
        this.timestamp = timestamp;
        this.data = data; // Medical record data
        this.previousHash = previousHash;
        this.hash = this.calculateHash();
    }

    // Compute the SHA-256 hash of this block's content using our manual sha256 function.
    calculateHash() {
        return sha256(this.index + this.previousHash + this.timestamp + JSON.stringify(this.data));
    }
}

// Blockchain class to manage the chain of blocks.
class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
    }

    // Create the first block in the blockchain.
    createGenesisBlock() {
        return new Block(0, Date.now(), "Genesis Block", "0");
    }

    // Retrieve the most recent block.
    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    // Add a new block to the blockchain.
    addBlock(newBlock) {
        newBlock.previousHash = this.getLatestBlock().hash;
        newBlock.hash = newBlock.calculateHash();
        this.chain.push(newBlock);
    }

    // Verify the integrity of the blockchain.
    isChainValid() {
        for (let i = 1; i < this.chain.length; i++) {
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if (currentBlock.hash !== currentBlock.calculateHash()) return false;
            if (currentBlock.previousHash !== previousBlock.hash) return false;
        }
        return true;
    }
}

// MedicalRecord class defines the structure for a record.
class MedicalRecord {
    constructor(patientId, name, diagnosis, treatment, date) {
        this.patientId = patientId;
        this.name = name;
        this.diagnosis = diagnosis;
        this.treatment = treatment;
        this.date = date;
    }
}

// Instantiate the blockchain.
let medChain = new Blockchain();

// ----------------------------
// Routes
// ----------------------------

// Serve the main form to add records.
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Add loading animation
app.use((req, res, next) => {
    res.locals.loadingAnimation = `
    <div class="loader">
        <div class="loader-spinner"></div>
    </div>
    <style>
        .loader {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255,255,255,0.9);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            animation: fadeOut 0.5s 1s forwards;
        }
        .loader-spinner {
            width: 50px;
            height: 50px;
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        @keyframes fadeOut {
            to { opacity: 0; visibility: hidden; }
        }
    </style>
    `;
    next();
});

// Handle form submission to add a new medical record.
app.post("/addRecord", (req, res) => {
    const { patientId, name, diagnosis, treatment, date } = req.body;
    const record = new MedicalRecord(patientId, name, diagnosis, treatment, date);
    const newBlock = new Block(medChain.chain.length, Date.now(), record);
    medChain.addBlock(newBlock);
    res.redirect("/records");
});

// Display all records in a book-like view.
app.get("/records", (req, res) => {
    let recordsHTML = `<h2>Blockchain Records (Book View)</h2>`;
    medChain.chain.forEach((block, i) => {
        // For non-genesis blocks, check if they are out of sync.
        let warning = "";
        if (i > 0 && block.previousHash !== medChain.chain[i - 1].hash) {
            warning = `<p style="color:red;font-weight:bold;">Warning: Previous block has changed. Please sync this block.</p>`;
        }
        recordsHTML += `
            <div class="page">
                <h3>Block #${block.index}</h3>
                <p><strong>Timestamp:</strong> ${new Date(block.timestamp).toLocaleString()}</p>
                <p><strong>Hash:</strong> ${block.hash}</p>
                <p><strong>Previous Hash:</strong> ${block.previousHash}</p>
                <p><strong>Data:</strong><br>
                    Patient ID: ${block.data.patientId || block.data}<br>
                    Name: ${block.data.name || ""}<br>
                    Diagnosis: ${block.data.diagnosis || ""}<br>
                    Treatment: ${block.data.treatment || ""}<br>
                    Date: ${block.data.date || ""}</p>
                ${warning}
                ${
                  // Only show Edit and Sync buttons for non-genesis blocks.
                  block.index > 0
                    ? `<a href="/edit/${block.index}">
                           <button style="margin-top:10px;padding:8px 12px;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer;">Edit</button>
                       </a>
                       <a href="/sync/${block.index}">
                           <button style="margin-top:10px;padding:8px 12px;background:#e67e22;color:white;border:none;border-radius:4px;cursor:pointer;margin-left:10px;">Sync</button>
                       </a>`
                    : ""
                }
            </div>
        `;
    });
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Blockchain Records</title>
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            ${res.locals.loadingAnimation}
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: 'Roboto', sans-serif; background-color: #f8f9fa; color: #333; }
                header { background-color: #3498db; padding: 15px; text-align: center; color: white; }
                nav a { color: white; margin: 0 15px; text-decoration: none; font-weight: 500; }
                .container { max-width: 800px; margin: 20px auto; padding: 20px; }
                .page {
                    background: #fff;
                    margin: 20px 0;
                    padding: 25px;
                    border: 1px solid #eaeaea;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                    border-radius: 12px;
                    transform: translateY(0);
                    transition: all 0.3s ease;
                    opacity: 0;
                    animation: fadeInUp 0.6s ease forwards;
                }
                @keyframes fadeInUp {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .page:hover { transform: translateY(-5px); box-shadow: 0 6px 16px rgba(0,0,0,0.12); }
                .nav-links { text-align: center; margin-top: 20px; }
                .nav-links a { margin: 0 10px; text-decoration: none; color: #3498db; font-weight: 500; }
                @media (max-width: 768px) {
                    .container { padding: 15px; }
                    header nav a { display: block; margin: 10px 0; }
                    .page { margin: 15px 0; padding: 20px; }
                }
            </style>
        </head>
        <body>
            <header>
                <h1>Blockchain Medical Records</h1>
                <nav>
                    <a href="/">Input Record</a>
                    <a href="/records">View Records</a>
                    <a href="/search">Search Records</a>
                </nav>
            </header>
            <div class="container">
                ${recordsHTML}
                <div class="nav-links">
                    <a href="/">Back to Home</a> | 
                    <a href="/search">Search Record by Hash</a>
                </div>
            </div>
        </body>
        </html>
    `);
});

app.get("/edit/:index", (req, res) => {
    const index = parseInt(req.params.index);
    if (isNaN(index) || index < 0 || index >= medChain.chain.length) {
        return res.status(400).send("Invalid block index.");
    }
    const block = medChain.chain[index];
    // Prevent editing of the Genesis block.
    if (block.index === 0) {
        return res.status(400).send("Genesis block cannot be edited.");
    }
    const record = block.data; // The record data object

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Edit Medical Record</title>
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: 'Roboto', sans-serif; background-color: #f8f9fa; color: #333; }
                header { background-color: #3498db; padding: 15px; text-align: center; color: white; }
                nav a { color: white; margin: 0 15px; text-decoration: none; font-weight: 500; }
                .container { max-width: 800px; margin: 20px auto; padding: 20px; }
                .form-container {
                    background: #fff;
                    padding: 40px;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                    transition: all 0.3s ease;
                }
                h1 { margin-bottom: 20px; text-align: center; }
                label { font-weight: 500; margin-bottom: 5px; display: block; }
                input[type="text"],
                input[type="date"] {
                    width: 100%;
                    padding: 10px;
                    margin-bottom: 15px;
                    border: 2px solid #e0e0e0;
                    border-radius: 4px;
                    font-size: 1rem;
                    transition: all 0.3s ease;
                }
                input[type="text"]:focus,
                input[type="date"]:focus {
                    border-color: #3498db;
                    box-shadow: 0 2px 8px rgba(52,152,219,0.2);
                }
                input[type="submit"] {
                    width: 100%;
                    padding: 15px;
                    font-size: 1.1rem;
                    background-image: linear-gradient(to right, #3498db, #2980b9);
                    border: none;
                    border-radius: 4px;
                    color: white;
                    cursor: pointer;
                    transition: background-color 0.3s ease;
                }
                input[type="submit"]:hover {
                    background-color: #2980b9;
                }
                @media (max-width: 768px) {
                    .container { padding: 15px; }
                    header nav a { display: block; margin: 10px 0; }
                    .form-container { padding: 25px; }
                }
            </style>
        </head>
        <body>
            <header>
                <h1>Edit Medical Record</h1>
                <nav>
                    <a href="/">Input Record</a>
                    <a href="/records">View Records</a>
                    <a href="/search">Search Records</a>
                </nav>
            </header>
            <div class="container">
                <div class="form-container">
                    <form action="/editRecord" method="POST">
                        <input type="hidden" id="index" name="index" value="${block.index}">
                        
                        <label for="patientId">Patient ID:</label>
                        <input type="text" id="patientId" name="patientId" value="${record.patientId}" required>
                        
                        <label for="name">Name:</label>
                        <input type="text" id="name" name="name" value="${record.name}" required>
                        
                        <label for="diagnosis">Diagnosis:</label>
                        <input type="text" id="diagnosis" name="diagnosis" value="${record.diagnosis}" required>
                        
                        <label for="treatment">Treatment:</label>
                        <input type="text" id="treatment" name="treatment" value="${record.treatment}" required>
                        
                        <label for="date">Date:</label>
                        <input type="date" id="date" name="date" value="${record.date}" required>
                        
                        <input type="submit" value="Edit Record">
                    </form>
                </div>
            </div>
        </body>
        </html>
    `);
});

// Route to sync a block's connectivity
app.get("/sync/:index", (req, res) => {
    const index = parseInt(req.params.index);
    if (isNaN(index) || index <= 0 || index >= medChain.chain.length) {
        return res.status(400).send("Invalid block index for sync.");
    }
    // Update this block's previous hash and recalc its hash.
    medChain.chain[index].previousHash = medChain.chain[index - 1].hash;
    medChain.chain[index].hash = medChain.chain[index].calculateHash();
    res.redirect("/records");
});

// Route to handle editing an existing record
app.post("/editRecord", (req, res) => {
    const { index, patientId, name, diagnosis, treatment, date } = req.body;
    
    if (index < 0 || index >= medChain.chain.length) {
        return res.status(400).send("Invalid block index.");
    }

    // Update only the specified block’s data and recalc its own hash.
    medChain.chain[index].data = new MedicalRecord(patientId, name, diagnosis, treatment, date);
    medChain.chain[index].hash = medChain.chain[index].calculateHash();

    res.redirect("/records");
});

// Serve the search form page.
app.get("/search", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "search.html"));
});

// Handle search query by block hash.
app.get("/searchResult", (req, res) => {
    const hashQuery = req.query.hash;
    const block = medChain.chain.find((b) => b.hash === hashQuery);
    let resultHTML = `<h2>Search Result</h2>`;
    if (block) {
        resultHTML += `
            <div class="page">
                <h3>Block #${block.index}</h3>
                <p><strong>Timestamp:</strong> ${new Date(block.timestamp).toLocaleString()}</p>
                <p><strong>Hash:</strong> ${block.hash}</p>
                <p><strong>Previous Hash:</strong> ${block.previousHash}</p>
                <p><strong>Data:</strong><br>
                    Patient ID: ${block.data.patientId || block.data}<br>
                    Name: ${block.data.name || ""}<br>
                    Diagnosis: ${block.data.diagnosis || ""}<br>
                    Treatment: ${block.data.treatment || ""}<br>
                    Date: ${block.data.date || ""}</p>
            </div>
        `;
    } else {
        resultHTML += `<p>No record found for hash: ${hashQuery}</p>`;
    }
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Blockchain Records</title>
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            ${res.locals.loadingAnimation}
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: 'Roboto', sans-serif; background-color: #f8f9fa; color: #333; }
                header { background-color: #3498db; padding: 15px; text-align: center; color: white; }
                nav a { color: white; margin: 0 15px; text-decoration: none; font-weight: 500; }
                .container { max-width: 800px; margin: 20px auto; padding: 20px; }
                .page {
                    background: #fff;
                    margin: 20px 0;
                    padding: 20px;
                    border: 1px solid #ddd;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    border-radius: 8px;
                }
                h2 { text-align: center; margin-bottom: 20px; }
                .nav-links { text-align: center; margin-top: 20px; }
                .nav-links a { margin: 0 10px; text-decoration: none; color: #3498db; font-weight: 500; }
            </style>
        </head>
        <body>
            <header>
                <h1>Blockchain Medical Records</h1>
                <nav>
                    <a href="/">Input Record</a>
                    <a href="/records">View Records</a>
                    <a href="/search">Search Records</a>
                </nav>
            </header>
            <div class="container">
                ${resultHTML}
                <div class="nav-links">
                    <a href="/">Back to Home</a> | 
                    <a href="/search">Search Record by Hash</a>
                </div>
            </div>
        </body>
        </html>
    `);
});

// Start the server.
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
