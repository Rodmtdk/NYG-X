const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

sgMail.setApiKey(process.env.SENDGRID_API_KEY);
mongoose.connect(process.env.DATABASE_URL);

const User = mongoose.model('User', new mongoose.Schema({
    email: String,
    banned: { type: Boolean, default: false },
    warnings: { type: Number, default: 0 }
}));

const verifyJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).send('Token requis.');
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send('Token invalide.');
        req.user = decoded;
        next();
    });
};

app.post('/login', async (req, res) => {
    const { email } = req.body;

    if (email !== "rod.mtdk.gng@gmail.com")
        return res.status(403).send("Email non autorisé.");

    let user = await User.findOne({ email });
    if (!user) {
        user = new User({ email });
        await user.save();
    }
    if (user.banned) return res.status(403).send("Utilisateur banni.");

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
});

app.get('/verify-user', verifyJWT, (req, res) => {
    res.json({ access: true });
});

app.get('/get-users', verifyJWT, async (req, res) => {
    const filter = req.query.filter || '';
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const query = { email: new RegExp(filter, 'i') };
    const users = await User.find(query).skip((page - 1) * limit).limit(limit);
    const total = await User.countDocuments(query);
    res.json({ users, total, page, totalPages: Math.ceil(total / limit) });
});

app.post('/ban-user', verifyJWT, async (req, res) => {
    const { email } = req.body;
    await User.updateOne({ email }, { banned: true });
    try {
        await sgMail.send({
            to: email,
            from: 'no-reply@nyg-x.com',
            subject: 'Compte banni - NYG-X',
            text: 'Votre compte a été banni pour violation des règles.'
        });
    } catch (err) {
        console.error("Erreur envoi mail :", err.message);
    }
    res.json({ success: true });
});

app.use((req, res) => {
    res.status(404).json({ message: 'Route introuvable' });
});

app.listen(3000, () => console.log('Serveur NYG-X actif sur http://localhost:3000'));
