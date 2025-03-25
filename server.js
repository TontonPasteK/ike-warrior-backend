/**************************************************************
 * server.js - Authentification avec bcrypt + JWT
 **************************************************************/

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3001;

// Clé secrète pour signer les JWT
const JWT_SECRET = '180993';

// Middlewares
app.use(cors());
app.use(express.json());

// ***************************************
// 1) Configuration du Pool PostgreSQL
// ***************************************
const pool = new Pool({
  connectionString: 'postgresql://ike_warrior_db_user:63K3iTRztqjax8WqVA4KVAL1dBzqAw9j@dpg-cvg4m4vnoe9s73bmdn0g-a.oregon-postgres.render.com/ike_warrior_db',
  ssl: {
    rejectUnauthorized: false
  }
});


/**************************************************************
 * 2) Route d'inscription (POST /api/register)
 **************************************************************/
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    // Vérifier si l'email existe déjà
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email déjà utilisé' });
    }

    // Hasher le mot de passe
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insérer l'utilisateur avec role='user'
    await pool.query(
      `INSERT INTO users (username, email, password, role)
       VALUES ($1, $2, $3, 'user')`,
      [username, email, hashedPassword]
    );

    res.json({ message: 'Inscription réussie' });
  } catch (err) {
    console.error('Erreur register:', err);
    res.status(500).json({ error: 'Erreur interne' });
  }
});

/**************************************************************
 * 3) Route de connexion (POST /api/login)
 *    - Vérifie l'utilisateur par email
 *    - Compare le mot de passe haché avec bcrypt
 *    - Génère un token JWT en cas de succès
 **************************************************************/
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    // Vérifier si l'utilisateur existe
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length === 0) {
      return res.status(400).json({ error: 'Utilisateur non trouvé' });
    }

    const user = userCheck.rows[0];
    // Comparer le mot de passe en clair avec le hash
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Mot de passe incorrect' });
    }

    // Générer un token JWT contenant userId et role
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }  // token valable 1h
    );

    res.json({ token });
  } catch (err) {
    console.error('Erreur login:', err);
    res.status(500).json({ error: 'Erreur interne' });
  }
});

/**************************************************************
 * 4) Middleware d'authentification JWT
 **************************************************************/
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Token manquant' });
  }

  // Le header doit être "Bearer <token>"
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalide' });
    }
    // user = { userId, role, iat, exp }
    req.user = user;
    next();
  });
}

/**************************************************************
 * 5) Middleware de vérification du rôle admin
 **************************************************************/
function checkAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit: rôle admin requis' });
  }
  next();
}

/**************************************************************
 * 6) Route d'accueil
 **************************************************************/
app.get('/', (req, res) => {
  res.send('Hello from Ike Warrior Backend with PostgreSQL + Auth!');
});

/**************************************************************
 * 7) Route GET /api/users (protégée par JWT)
 **************************************************************/
app.get('/api/users', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/**************************************************************
 * 8) Route POST /api/buy-tokens (protégée par JWT)
 **************************************************************/
app.post('/api/buy-tokens', authenticateJWT, async (req, res) => {
  const { userId, amountInvested } = req.body;
  try {
    await pool.query(
      `UPDATE users
       SET has_purchased_tokens = true
       WHERE id = $1`,
      [userId]
    );

    let rewardPoints = 0;
    if (amountInvested >= 1000) {
      rewardPoints = 100;
    } else if (amountInvested >= 500) {
      rewardPoints = 50;
    } else if (amountInvested >= 100) {
      rewardPoints = 10;
    }

    if (rewardPoints > 0) {
      await pool.query(
        `UPDATE users
         SET points = points + $1
         WHERE id = $2`,
        [rewardPoints, userId]
      );
    }

    res.json({
      message: 'Achat de tokens réussi',
      hasPurchasedTokens: true,
      rewardPoints
    });
  } catch (err) {
    console.error("Erreur lors de l'achat de tokens :", err);
    res.status(500).json({ error: "Erreur lors de l'achat de tokens." });
  }
});

/**************************************************************
 * 9) Route POST /api/add-points (protégée par JWT)
 **************************************************************/
app.post('/api/add-points', authenticateJWT, async (req, res) => {
  const { userId, pointsToAdd } = req.body;
  try {
    await pool.query(
      `UPDATE users
       SET points = points + $1
       WHERE id = $2`,
      [pointsToAdd, userId]
    );

    const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const updatedUser = result.rows[0];

    res.json({
      message: 'Points ajoutés avec succès.',
      user: updatedUser
    });
  } catch (err) {
    console.error("Erreur lors de l'ajout de points :", err);
    res.status(500).json({ error: "Erreur lors de l'ajout de points." });
  }
});

/**************************************************************
 * 10) Route admin (GET /api/admin/users)
 * Protégée par JWT + checkAdmin
 **************************************************************/
app.get('/api/admin/users', authenticateJWT, checkAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users');
    res.json(result.rows);
  } catch (err) {
    console.error('Erreur admin/users :', err);
    res.status(500).json({ error: 'Erreur interne.' });
  }
});

/**************************************************************
 * Lancement du serveur
 **************************************************************/
app.listen(port, () => {
  console.log(`Serveur démarré sur le port ${port}`);
});
