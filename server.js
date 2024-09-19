const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path'); // Importar path para servir arquivos estáticos
const app = express();
const User = require('./models/User');
const CollectionPoint = require('./models/CollectionPoint');
const Appointment = require('./models/Appointment')
require('dotenv').config();

// Configuração do CORS
app.use(cors({
    origin: 'https://5c3ee3cc-707a-4f69-b6b2-f81a151a6a08-00-21l3zcjszobfl.spock.replit.dev', //Qualquer Origem
    credentials: true
}));

// Configurar o parser de JSON e cookies
app.use(express.json());
app.use(cookieParser());

// Conectar ao MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Conectado ao MongoDB'))
.catch(err => console.error('Erro ao conectar ao MongoDB', err));

// Middleware para verificar o token
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Acesso negado' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Token inválido' });
        req.user = user; // O ID do usuário deve estar aqui
        next();
    });
};


// Middleware para redirecionar usuários logados da página de login para o perfil
const redirectIfLoggedIn = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err) => {
            if (!err) return res.redirect('/profile.html');
            next();
        });
    } else {
        next();
    }
};


// Middleware para redirecionar usuários não autenticados da página de perfil para a página de login
const redirectIfNotLoggedIn = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.redirect('/');
    jwt.verify(token, process.env.JWT_SECRET, (err) => {
        if (err) return res.redirect('/');
        next();
    });
};


// Rota de registro
app.post('/api/register', async (req, res) => {
    const { name, email, address, password, role } = req.body;

    // Verifica se o papel (role) é válido
    if (!['donor', 'collector'].includes(role)) {
        return res.status(400).json({ success: false, message: 'Tipo de usuário inválido' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Usuário já existe' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, address, password: hashedPassword, role });
        await newUser.save();
        res.status(201).json({ success: true, message: 'Usuário registrado com sucesso!' });
    } catch (error) {
        console.error('Erro ao registrar usuário:', error);
        res.status(500).json({ success: false, message: 'Erro ao registrar usuário' });
    }
});















// Rota de login com JWT
app.post('/api/login', async (req, res) => {
    const { email, password, role } = req.body; 
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Usuário não encontrado' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Senha incorreta' });
        }

        // Verificar se o papel do usuário corresponde ao papel informado na solicitação
        if (user.role !== role) {
            return res.status(403).json({ success: false, message: 'Tipo de usuário errado' });
        }

        // Incluindo o ID do usuário no payload do token
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'None', secure: true });
        res.json({ success: true, token });
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        res.status(500).json({ success: false, message: 'Erro ao fazer login' });
    }
});
// Rota para obter dados do usuário
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
        res.json({ success: true, user });
    } catch (error) {
        console.error('Erro ao obter perfil do usuário:', error);
        res.status(500).json({ success: false, message: 'Erro ao obter perfil do usuário' });
    }
});














// Iniciar o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));