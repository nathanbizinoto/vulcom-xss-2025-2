const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const validator = require('validator');
const app = express();

const db = new sqlite3.Database(':memory:');

// Configurações de segurança
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Criar tabela de comentários vulnerável
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão seguro
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { 
            httpOnly: true,  // Protege contra acesso via JavaScript
            secure: false,   // Para desenvolvimento local (usar true em HTTPS)
            sameSite: 'strict' // Protege contra CSRF
        });
    }
    next();
});

// Rota principal
app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) {
            return res.send('Erro ao carregar comentários');
        }
        res.render('comments', { comments: rows });
    });
});

// Rota para enviar comentários (PROTEGIDA contra XSS ✅)
app.post('/comment', (req, res) => {
    const { content } = req.body;
    
    // Validação e sanitização da entrada
    if (!content || content.trim().length === 0) {
        return res.status(400).send('Comentário não pode estar vazio');
    }
    
    if (content.length > 1000) {
        return res.status(400).send('Comentário muito longo (máximo 1000 caracteres)');
    }
    
    // Sanitização: escape de caracteres HTML perigosos
    const sanitizedContent = validator.escape(content);
    
    db.run("INSERT INTO comments (content) VALUES (?)", [sanitizedContent], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
