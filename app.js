const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const session = require("express-session");

const app = express();
const port = process.env.PORT || 3000;

// Middleware untuk parse URL-encoded data dan menyajikan file statis
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Konfigurasi session
app.use(session({
    secret: "secretKeyUntukSession", // ganti dengan secret yang lebih aman
    resave: false,
    saveUninitialized: false
}));

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

    // Convert string menjadi array 32-bit words
    var words = [];
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = i >> 2;
        words[j] = (words[j] || 0) | (ascii.charCodeAt(i) << ((3 - (i % 4)) * 8));
    }

    // Proses pesan dalam blok 512-bit
    for (j = 0; j < words[lengthProperty]; j += 16) {
        var w = words.slice(j, j + 16);
        var oldHash = hash.slice(0);

        // Extend blok 16 word menjadi 64 words
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

        // Tambahkan hash blok ini ke hasil sebelumnya:
        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }

    // Hasil akhir hash dalam bentuk hex string.
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

// Block class untuk tiap block dalam chain.
class Block {
    constructor(index, timestamp, data, previousHash = "") {
        this.index = index;
        this.timestamp = timestamp;
        this.data = data; // Data record medis (termasuk informasi pembuat)
        this.previousHash = previousHash;
        this.hash = this.calculateHash();
    }

    // Hitung hash SHA-256 dari konten block ini.
    calculateHash() {
        return sha256(this.index + this.previousHash + this.timestamp + JSON.stringify(this.data));
    }
}

// Blockchain class untuk mengelola chain blok.
class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
    }

    // Membuat blok pertama di blockchain.
    createGenesisBlock() {
        return new Block(0, Date.now(), "Genesis Block", "0");
    }

    // Mendapatkan blok terakhir.
    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    // Menambahkan blok baru ke dalam blockchain.
    addBlock(newBlock) {
        newBlock.previousHash = this.getLatestBlock().hash;
        newBlock.hash = newBlock.calculateHash();
        this.chain.push(newBlock);
    }

    // Mengecek integritas blockchain.
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

// MedicalRecord class (tambahkan properti createdBy untuk menyimpan siapa pembuat record)
class MedicalRecord {
    constructor(patientId, name, diagnosis, treatment, date, createdBy) {
        this.patientId = patientId;
        this.name = name;
        this.diagnosis = diagnosis;
        this.treatment = treatment;
        this.date = date;
        this.createdBy = createdBy; // username pembuat record
    }
}

// Menyimpan data blockchain
let medChain = new Blockchain();

// Simulasi penyimpanan user (hanya untuk contoh; gunakan database di aplikasi sebenarnya)
const users = {}; // format: { username: { password: "plaintext", ... } }

// ----------------------------
// Middleware Autentikasi
// ----------------------------

function isAuthenticated(req, res, next) {
    if (req.session && req.session.username) {
        return next();
    }
    res.redirect("/login");
}

// ----------------------------
// Routes untuk User (Register & Login)
// ----------------------------

// Halaman registrasi
app.get("/register", (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MedChain - Register</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f7fa;
                    padding: 0;
                    margin: 0;
                    color: #333;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                }
                .container {
                    width: 100%;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .auth-container {
                    display: flex;
                    box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
                    border-radius: 10px;
                    overflow: hidden;
                    background: white;
                }
                .auth-image {
                    flex: 1;
                    background-image: url('https://via.placeholder.com/800x600/4a90e2/ffffff?text=MedChain');
                    background-size: cover;
                    background-position: center;
                    display: flex;
                    flex-direction: column;
                    justify-content: flex-end;
                    padding: 30px;
                    color: white;
                    position: relative;
                }
                .auth-image::before {
                    content: '';
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    right: 0;
                    height: 70%;
                    background: linear-gradient(to top, rgba(0,0,0,0.7), transparent);
                    z-index: 1;
                }
                .auth-image-content {
                    position: relative;
                    z-index: 2;
                }
                .auth-form {
                    flex: 1;
                    padding: 40px;
                }
                h1 {
                    color: #2c3e50;
                    margin-bottom: 10px;
                    font-weight: 600;
                }
                h2 {
                    color: #2c3e50;
                    margin-top: 0;
                    margin-bottom: 30px;
                    font-weight: 400;
                    font-size: 18px;
                }
                .logo {
                    margin-bottom: 30px;
                    display: flex;
                    align-items: center;
                    font-size: 24px;
                    font-weight: bold;
                    color: #3498db;
                }
                .logo span {
                    color: #2c3e50;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                .form-group label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 500;
                    color: #555;
                }
                .form-control {
                    width: 100%;
                    padding: 12px 15px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 15px;
                    transition: border-color 0.3s;
                }
                .form-control:focus {
                    border-color: #3498db;
                    outline: none;
                }
                .btn {
                    background-color: #3498db;
                    color: white;
                    border: none;
                    padding: 12px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                    font-weight: 500;
                    width: 100%;
                    transition: background-color 0.3s;
                }
                .btn:hover {
                    background-color: #2980b9;
                }
                .auth-footer {
                    margin-top: 25px;
                    text-align: center;
                    color: #7f8c8d;
                }
                .auth-footer a {
                    color: #3498db;
                    text-decoration: none;
                    font-weight: 500;
                }
                .auth-footer a:hover {
                    text-decoration: underline;
                }
                .features {
                    margin-top: 20px;
                    font-size: 14px;
                }
                .feature-item {
                    margin-bottom: 10px;
                    display: flex;
                    align-items: center;
                }
                .feature-icon {
                    margin-right: 10px;
                    font-weight: bold;
                    color: #2ecc71;
                }
                .role-selector {
                    display: flex;
                    margin-bottom: 20px;
                    gap: 15px;
                }
                .role-option {
                    flex: 1;
                    padding: 15px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    text-align: center;
                    cursor: pointer;
                    transition: all 0.3s;
                }
                .role-option:hover {
                    border-color: #3498db;
                }
                .role-option.selected {
                    border-color: #3498db;
                    background-color: rgba(52, 152, 219, 0.1);
                }
                .role-option-icon {
                    font-size: 24px;
                    margin-bottom: 10px;
                }
                @media (max-width: 768px) {
                    .auth-image {
                        display: none;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="auth-container">
                    <div class="auth-image">
                        <div class="auth-image-content">
                            <h1>MedChain</h1>
                            <p>Bergabunglah dengan sistem rekam medis berbasis blockchain yang menjamin keamanan dan integritas data.</p>
                            <div class="features">
                                <div class="feature-item">
                                    <span class="feature-icon">✓</span> Verifikasi data dengan teknologi blockchain
                                </div>
                                <div class="feature-item">
                                    <span class="feature-icon">✓</span> Keamanan data sesuai standar medis
                                </div>
                                <div class="feature-item">
                                    <span class="feature-icon">✓</span> Akses multi-perangkat yang aman
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="auth-form">
                        <div class="logo">Med<span>Chain</span></div>
                        <h1>Buat Akun Baru</h1>
                        <h2>Daftar untuk mengakses sistem rekam medis blockchain</h2>
                        
                        <form method="POST" action="/register">
                            <div class="role-selector">
                                <div class="role-option" onclick="selectRole('doctor')">
                                    <div class="role-option-icon">👨‍⚕️</div>
                                    <div>Dokter</div>
                                </div>
                                <div class="role-option" onclick="selectRole('nurse')">
                                    <div class="role-option-icon">👩‍⚕️</div>
                                    <div>Perawat</div>
                                </div>
                                <div class="role-option" onclick="selectRole('admin')">
                                    <div class="role-option-icon">👩‍💼</div>
                                    <div>Admin</div>
                                </div>
                            </div>
                            <input type="hidden" id="role" name="role" value="doctor">
                            
                            <div class="form-group">
                                <label for="fullname">Nama Lengkap</label>
                                <input type="text" id="fullname" name="fullname" class="form-control" placeholder="Masukkan nama lengkap" required />
                            </div>
                            
                            <div class="form-group">
                                <label for="username">Username</label>
                                <input type="text" id="username" name="username" class="form-control" placeholder="Buat username" required />
                            </div>
                            
                            <div class="form-group">
                                <label for="email">Email</label>
                                <input type="email" id="email" name="email" class="form-control" placeholder="Masukkan email" required />
                            </div>
                            
                            <div class="form-group">
                                <label for="password">Password</label>
                                <input type="password" id="password" name="password" class="form-control" placeholder="Buat password" required />
                            </div>
                            
                            <div class="form-group">
                                <label for="confirm_password">Konfirmasi Password</label>
                                <input type="password" id="confirm_password" name="confirm_password" class="form-control" placeholder="Konfirmasi password" required />
                            </div>
                            
                            <button type="submit" class="btn">Daftar Sekarang</button>
                        </form>
                        
                        <div class="auth-footer">
                            <p>Sudah memiliki akun? <a href="/login">Masuk di sini</a></p>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                function selectRole(role) {
                    // Remove selected class from all options
                    document.querySelectorAll('.role-option').forEach(option => {
                        option.classList.remove('selected');
                    });
                    
                    // Add selected class to clicked option
                    event.currentTarget.classList.add('selected');
                    
                    // Update hidden input value
                    document.getElementById('role').value = role;
                }
                
                // Select doctor role by default
                document.addEventListener('DOMContentLoaded', function() {
                    document.querySelector('.role-option').classList.add('selected');
                });
            </script>
        </body>
        </html>
    `);
});

app.post("/register", (req, res) => {
    const { username, password } = req.body;
    if (users[username]) {
        return res.send("Username sudah terdaftar. <a href='/register'>Coba lagi</a>");
    }
    // Simpan user (perlu diingat: password dalam plaintext tidak aman untuk produksi)
    users[username] = { password };
    req.session.username = username;
    res.redirect("/");
});

// Halaman login
app.get("/login", (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MedChain - Login</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f7fa;
                    padding: 0;
                    margin: 0;
                    color: #333;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                }
                .container {
                    width: 100%;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .auth-container {
                    display: flex;
                    box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
                    border-radius: 10px;
                    overflow: hidden;
                    background: white;
                }
                .auth-image {
                    flex: 1;
                    background-image: url('https://via.placeholder.com/800x600/4a90e2/ffffff?text=MedChain');
                    background-size: cover;
                    background-position: center;
                    display: flex;
                    flex-direction: column;
                    justify-content: flex-end;
                    padding: 30px;
                    color: white;
                    position: relative;
                }
                .auth-image::before {
                    content: '';
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    right: 0;
                    height: 70%;
                    background: linear-gradient(to top, rgba(0,0,0,0.7), transparent);
                    z-index: 1;
                }
                .auth-image-content {
                    position: relative;
                    z-index: 2;
                }
                .auth-form {
                    flex: 1;
                    padding: 40px;
                }
                h1 {
                    color: #2c3e50;
                    margin-bottom: 10px;
                    font-weight: 600;
                }
                h2 {
                    color: #2c3e50;
                    margin-top: 0;
                    margin-bottom: 30px;
                    font-weight: 400;
                    font-size: 18px;
                }
                .logo {
                    margin-bottom: 30px;
                    display: flex;
                    align-items: center;
                    font-size: 24px;
                    font-weight: bold;
                    color: #3498db;
                }
                .logo span {
                    color: #2c3e50;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                .form-group label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 500;
                    color: #555;
                }
                .form-control {
                    width: 100%;
                    padding: 12px 15px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 15px;
                    transition: border-color 0.3s;
                }
                .form-control:focus {
                    border-color: #3498db;
                    outline: none;
                }
                .btn {
                    background-color: #3498db;
                    color: white;
                    border: none;
                    padding: 12px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                    font-weight: 500;
                    width: 100%;
                    transition: background-color 0.3s;
                }
                .btn:hover {
                    background-color: #2980b9;
                }
                .auth-footer {
                    margin-top: 25px;
                    text-align: center;
                    color: #7f8c8d;
                }
                .auth-footer a {
                    color: #3498db;
                    text-decoration: none;
                    font-weight: 500;
                }
                .auth-footer a:hover {
                    text-decoration: underline;
                }
                .features {
                    margin-top: 20px;
                    font-size: 14px;
                }
                .feature-item {
                    margin-bottom: 10px;
                    display: flex;
                    align-items: center;
                }
                .feature-icon {
                    margin-right: 10px;
                    font-weight: bold;
                    color: #2ecc71;
                }
                @media (max-width: 768px) {
                    .auth-image {
                        display: none;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="auth-container">
                    <div class="auth-image">
                        <div class="auth-image-content">
                            <h1>MedChain</h1>
                            <p>Sistem rekam medis aman berbasis blockchain untuk menjaga kerahasiaan dan integritas data pasien.</p>
                            <div class="features">
                                <div class="feature-item">
                                    <span class="feature-icon">✓</span> Data terdesentralisasi & tidak dapat dimanipulasi
                                </div>
                                <div class="feature-item">
                                    <span class="feature-icon">✓</span> Privasi pasien terjamin
                                </div>
                                <div class="feature-item">
                                    <span class="feature-icon">✓</span> Akses data medis secara real-time
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="auth-form">
                        <div class="logo">Med<span>Chain</span></div>
                        <h1>Selamat Datang Kembali</h1>
                        <h2>Masuk untuk mengakses sistem rekam medis</h2>
                        
                        <form method="POST" action="/login">
                            <div class="form-group">
                                <label for="username">Username</label>
                                <input type="text" id="username" name="username" class="form-control" placeholder="Masukkan username Anda" required />
                            </div>
                            <div class="form-group">
                                <label for="password">Password</label>
                                <input type="password" id="password" name="password" class="form-control" placeholder="Masukkan password Anda" required />
                            </div>
                            <button type="submit" class="btn">Masuk</button>
                        </form>
                        
                        <div class="auth-footer">
                            <p>Belum memiliki akun? <a href="/register">Daftar sekarang</a></p>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
    `);
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    if (user && user.password === password) {
        req.session.username = username;
        res.redirect("/");
    } else {
        res.send("Username atau password salah. <a href='/login'>Coba lagi</a>");
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy(err => {
        res.redirect("/login");
    });
});

// ----------------------------
// Routes untuk Blockchain Medical Records
// ----------------------------

// Halaman utama input record, hanya user yang sudah login dapat mengakses
app.get("/", isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Tambahkan loading animation
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

let rejectVotes = {};

// Helper: Tentukan block pertama yang tidak sinkron (broken block) dalam chain.
function getBrokenBlockIndex(chain) {
    // Jika tidak ditemukan ketidaksinkronan, kembalikan null.
    for (let i = 1; i < chain.length; i++) {
        if (chain[i].previousHash !== chain[i - 1].hash) {
            return i - 1; // broken block adalah block sebelumnya.
        }
    }
    return null;
}

// Handle form submission untuk menambahkan record. Hanya user yang login yang bisa menambah.
app.post("/addRecord", isAuthenticated, (req, res) => {
    const { patientId, name, diagnosis, treatment, date } = req.body;
    const createdBy = req.session.username;
    const record = new MedicalRecord(patientId, name, diagnosis, treatment, date, createdBy);
    const newBlock = new Block(medChain.chain.length, Date.now(), record);
    medChain.addBlock(newBlock);
    res.redirect("/records");
});

app.get("/records", isAuthenticated, (req, res) => {
    // Cari block pertama yang tidak sinkron.
    const brokenBlockIndex = getBrokenBlockIndex(medChain.chain);

    let recordsHTML = `<h2>Blockchain Records (Book View)</h2>`;
    medChain.chain.forEach((block, i) => {
        let warning = "";
        // Jika ada broken block dan block ini berada setelahnya,
        // tampilkan warning dengan mengacu pada brokenBlockIndex.
        if (brokenBlockIndex !== null && i > brokenBlockIndex) {
            // Jika block yang sedang dirender (block i) dibuat oleh user yang login,
            // tampilkan juga tombol Reject untuk melakukan vote reject terhadap brokenBlockIndex.
            if (block.data.createdBy === req.session.username) {
                warning = `<p style="color:red;font-weight:bold;">
                             Warning: Block #${brokenBlockIndex} telah diubah.
                             <a href="/reject/${brokenBlockIndex}">
                                 <button style="padding:5px 8px;background:#c0392b;color:white;border:none;border-radius:4px;cursor:pointer;">
                                     Reject
                                 </button>
                             </a>
                          </p>`;
            } else {
                warning = `<p style="color:red;font-weight:bold;">
                             Warning: Block #${brokenBlockIndex} telah diubah.
                          </p>`;
            }
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
                    Date: ${block.data.date || ""}<br>
                    Created By: ${block.data.createdBy || "N/A"}
                </p>
                ${ 
                  // Tampilkan tombol Edit & Sync hanya untuk block non-genesis,
                  // dan hanya jika user yang login adalah pembuat record.
                  block.index > 0 && block.data.createdBy === req.session.username
                    ? `<a href="/edit/${block.index}">
                           <button style="margin-top:10px;padding:8px 12px;background:#3498db;color:white;border:none;border-radius:4px;cursor:pointer;">
                               Edit
                           </button>
                       </a>
                       <a href="/sync/${block.index}">
                           <button style="margin-top:10px;padding:8px 12px;background:#e67e22;color:white;border:none;border-radius:4px;cursor:pointer;margin-left:10px;">
                               Sync
                           </button>
                       </a>`
                    : ""
                }
                ${warning}
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
                    <a href="/logout">Logout (${req.session.username})</a>
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

// Route edit record
app.get("/edit/:index", isAuthenticated, (req, res) => {
    const index = parseInt(req.params.index);
    if (isNaN(index) || index < 0 || index >= medChain.chain.length) {
        return res.status(400).send("Invalid block index.");
    }
    const block = medChain.chain[index];
    // Mencegah editing Genesis block.
    if (block.index === 0) {
        return res.status(400).send("Genesis block tidak dapat diedit.");
    }
    // Pastikan user yang login adalah pembuat record
    if (block.data.createdBy !== req.session.username) {
        return res.status(403).send("Anda tidak berhak mengedit record ini.");
    }
    const record = block.data; // Object data record

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
                    <a href="/logout">Logout (${req.session.username})</a>
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

// Route untuk menyinkronkan konektivitas block
app.get("/sync/:index", isAuthenticated, (req, res) => {
    const index = parseInt(req.params.index);
    if (isNaN(index) || index <= 0 || index >= medChain.chain.length) {
        return res.status(400).send("Invalid block index for sync.");
    }
    // Update previous hash dan recalc hash block.
    medChain.chain[index].previousHash = medChain.chain[index - 1].hash;
    medChain.chain[index].hash = medChain.chain[index].calculateHash();
    res.redirect("/records");
});

// Route untuk menangani edit record, dengan mekanisme backup data lama
app.post("/editRecord", isAuthenticated, (req, res) => {
    const { index, patientId, name, diagnosis, treatment, date } = req.body;
    
    if (index < 0 || index >= medChain.chain.length) {
        return res.status(400).send("Invalid block index.");
    }
    
    // Pastikan user yang login adalah pembuat record
    if (medChain.chain[index].data.createdBy !== req.session.username) {
        return res.status(403).send("Anda tidak berhak mengedit record ini.");
    }
    
    // Simpan backup data (jika belum ada) untuk keperluan restore
    if (!medChain.chain[index].previousData) {
        medChain.chain[index].previousData = medChain.chain[index].data;
    }
    
    // Update data record dan recalc hash block.
    medChain.chain[index].data = new MedicalRecord(patientId, name, diagnosis, treatment, date, req.session.username);
    medChain.chain[index].hash = medChain.chain[index].calculateHash();
    
    res.redirect("/records");
});

app.get("/reject/:index", isAuthenticated, (req, res) => {
    const blockIndex = parseInt(req.params.index); 
    if (isNaN(blockIndex) || blockIndex < 0 || blockIndex >= medChain.chain.length - 1) {
        return res.status(400).send("Invalid block index for reject.");
    }

    const nextBlock = medChain.chain[blockIndex + 1];
    // if (nextBlock.data.createdBy.trim().toLowerCase() !== req.session.username.trim().toLowerCase()) {
    //     return res.status(403).send("Anda tidak berhak melakukan reject untuk block ini karena Anda bukan pembuat block setelahnya.");
    // }

    if (!rejectVotes[blockIndex]) {
        rejectVotes[blockIndex] = [];
    }
    if (rejectVotes[blockIndex].includes(req.session.username)) {
        return res.send("Anda telah memberikan vote reject untuk block ini. <a href='/records'>Kembali</a>");
    }
    rejectVotes[blockIndex].push(req.session.username);

    const totalAfter = medChain.chain.length - blockIndex - 1;
    const votes = rejectVotes[blockIndex].length;

    if (votes > totalAfter / 2) {
        const modifiedBlock = medChain.chain[blockIndex];
        if (modifiedBlock.previousData) {
            modifiedBlock.data = modifiedBlock.previousData;
            delete modifiedBlock.previousData;
            modifiedBlock.hash = modifiedBlock.calculateHash();
            for (let i = blockIndex + 1; i < medChain.chain.length; i++) {
                medChain.chain[i].previousHash = medChain.chain[i - 1].hash;
                medChain.chain[i].hash = medChain.chain[i].calculateHash();
            }
            delete rejectVotes[blockIndex];
            return res.send(`Block #${blockIndex} telah di-restore karena mayoritas vote reject. <a href='/records'>Kembali</a>`);
        } else {
            return res.send(`Tidak ada data backup untuk block #${blockIndex}. <a href='/records'>Kembali</a>`);
        }
    }

    res.send(`Vote reject untuk block #${blockIndex} berhasil direkam (${votes} vote). <a href='/records'>Kembali</a>`);
});

// Route untuk menangani search record (tetap sama)
app.get("/search", isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "search.html"));
});

// Handle search query berdasarkan hash block
app.get("/searchResult", isAuthenticated, (req, res) => {
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
                    Date: ${block.data.date || ""}<br>
                    Created By: ${block.data.createdBy || "N/A"}
                </p>
            </div>
        `;
    } else {
        resultHTML += `<p>Record tidak ditemukan untuk hash: ${hashQuery}</p>`;
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
                    <a href="/logout">Logout (${req.session.username})</a>
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


// Halaman search
app.get("/search", isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "search.html"));
});

// Handle search query berdasarkan hash blok
app.get("/searchResult", isAuthenticated, (req, res) => {
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
                    Date: ${block.data.date || ""}<br>
                    Created By: ${block.data.createdBy || "N/A"}
                </p>
            </div>
        `;
    } else {
        resultHTML += `<p>Record tidak ditemukan untuk hash: ${hashQuery}</p>`;
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
                    <a href="/logout">Logout (${req.session.username})</a>
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

// Start server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
