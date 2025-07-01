require("dotenv").config();

const express  = require("express");
const mongoose = require("mongoose");
const bcrypt   = require("bcrypt");
const jwt      = require("jsonwebtoken");
const cors     = require("cors");

//  Modelos
const User = require("./models/User");

// Inicializa o app
const app = express();
app.use(express.json()); // Permitir JSON no corpo da requisição

app.use(cors()); // Permitir requisições de outros domínios

//  Rota de teste, se a api já esta a funcionar
app.get("/", (req, res) => {
  res.status(200).json({ message: "API está funcionando!" });
});

//  Rota de cadastro de usuário
app.post("/auth/register", async (req, res) => {
  const { username, email, password, confirmpassword } = req.body;

  //  Validações
  if (!username || !email || !password || !confirmpassword) {
    return res.status(400).json({ error: "Todos os campos são obrigatórios" });
  }

  if (password !== confirmpassword) {
    return res.status(400).json({ error: "As senhas não coincidem" });
  }

  try {
    //  Verificar se o e-mail já está cadastrado
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      return res.status(400).json({ error: "Esse e-mail já está cadastrado" });
    }

    //  Criptografa a senha
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    //  Cria o usuário
    const user = new User({
      username,
      email,
      password: passwordHash, 
    })

    //  Salva no banco de dados
    await user.save();

    res.status(201).json({ message: "Usuário registrado com sucesso" });

  } catch (error) {
    console.error(" Erro ao registrar usuário:", error)
    res.status(500).json({ error: "Erro ao registrar usuário", 

    })
  
}
})

//  Rota de login de usuário
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //validacão de email e senha
  if (!email || !password) {
    return res.status(400).json({ error: "E-mail e senha são obrigatórios" });
  }

  // Validações
  if (!email || !password) {
    return res.status(400).json({ error: "E-mail e senha são obrigatórios" });
  }

  try {
    // 👀 Verifica se o usuário existe
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(400).json({ error: "Usuário não encontrado" });
    }

    // 🔑 Verifica a senha
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: "Senha incorreta" });
    }

    // 🆔 Gera o token JWT
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || "secreta",
      { expiresIn: "1h" }
    );

    res.status(200).json({ message: "Login bem-sucedido", token });

  } catch (error) {
    console.error(" Erro ao fazer login:", error);
    res.status(500).json({ error: "Erro ao fazer login" });
  }
});

// 🔌 Conexão com MongoDB Atlas
const { DB_USER, DB_PASSWORD, PORT = 3000 } = process.env;

if (!DB_USER || !DB_PASSWORD) {
  console.error(" DB_USER ou DB_PASSWORD não foram definidos no .env");
  process.exit(1);
}

const uri = `mongodb+srv://${DB_USER}:${DB_PASSWORD}@cluster0.ddl88z4.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

mongoose
  .connect(uri)
  .then(() => {
    console.log("MongoDB conectado com sucesso");
    app.listen(PORT, () => {
      console.log(`🚀 Servidor rodando na porta ${PORT}`);
    });
  })
  .catch((err) => {
    console.error(" Erro ao conectar ao MongoDB:", err);
    process.exit(1);
  });
