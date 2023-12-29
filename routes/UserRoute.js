const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const UserModel = require('../models/User');
require('dotenv').config();

const router = express.Router();


const tokenSecretKey = process.env.SECRET_KEY




// Registrar um novo usuário
router.post('/cadastro', async (req, res) => {
  try {
    const { usuario, senha, email, whatsapp } = req.body;

    const existingUser = await UserModel.findOne({ usuario });
    if (existingUser) {
      return res.status(400).json({ message: 'Usuário já cadastrado, utilize outro.' });
    }

    const hashedPassword = await bcrypt.hash(senha, 10);

    const newUser = new UserModel({
      usuario,
      senha: hashedPassword,
      email,
      whatsapp,
    });

    await newUser.save();

    res.status(201).json({ message: `Usuário ${newUser.usuario} criado com sucesso.` });
  } catch (error) {
    res.status(500).json({ message: 'Ocorreu um erro ao criar o usuário.' });
  }
});

// Login do usuário
router.post('/', async (req, res) => {
  try {
    const { usuario, senha } = req.body;

    const user = await UserModel.findOne({ usuario });
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    const isPasswordCorrect = await bcrypt.compare(senha, user.senha);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: 'Senha incorreta, tente novamente.' });
    }





    
    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '1h' });

    res.status(200).json({ token, userID: user._id });
  } catch (error) {
    res.status(500).json({ message: 'Ocorreu um erro durante o login.' });
  }
});







// Buscar usuário por ID
router.get('/', async (req, res) => {
  try {
    const tokenHeader = req.headers.authorization;
    if (!tokenHeader) {
      return res.status(401).json({ message: 'Cabeçalho de autorização ausente.' });
    }

    const token = tokenHeader.split(' ')[1];
    const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
    const userId = decodedToken.id;

    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    res.status(200).json({ usuario: user.usuario });
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: `Token inválido. + ${error.message}`});
    }

    res.status(500).json({ message: 'Ocorreu um erro ao buscar o usuário.' });
  }
});

module.exports = {router,tokenSecretKey};
