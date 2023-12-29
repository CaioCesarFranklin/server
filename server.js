const express = require('express')
const cors = require('cors')
const UserModel = require('./models/User')
const EmpresaModel= require('./models/Empresa')
const AlimentosModel =  require('./models/Alimentos')
const jwt =require('jsonwebtoken')
const bcrypt = require('bcrypt')

require('dotenv').config()







const tokenSecretKey = process.env.SECRET_KEY
const port = process.env.PORT
const ADM = process.env.ADMID 
const app = express()
app.use(express.json())
app.use(cors())





const protect = async (req,res,next)=>{
    let token
    if (req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')){
        try {
            //Pegar o token do header
           
            token= req.headers.authorization.split(' ')[1]

            //verificar token
            const decodificar = jwt.verify(token,tokenSecretKey)
            // pegar o user do token

            req.user = await UserModel.findById(decodificar.id)
            next()
        } catch (error) {

            res.status(401).json({message:`error aqui o  ${error.message} `})
  
        }
    }
}






//Cadastrar ok!
app.post('/cadastro', async (req,res)=>{
try{
    
    const {usuario, senha,email,whatsapp,sexo} = req.body
    
if(!usuario){
        res.status(404).json({message: "Preencha usuario"})
 return
    }else if(!senha){  res.status(404).json({message: "Preencha senha"})
    return}else if(!email){ 
       res.status(404).json({message: "Preencha email"})
    return}
    else if(!email){ 
       res.status(404).json({message: "Preencha email"})
    return}   
    else if(!whatsapp){ 
      res.status(404).json({message: "Preencha whatsapp"})
   return}
   else if(!sexo){ 
    res.status(404).json({message: "Preencha sexo"})
 return}



const EmailCadastrado = await UserModel.findOne({email})   
if(EmailCadastrado){
    res.status(400).json({message: "E-mail já cadastrado"})
    return
} 

const WpCadastrado = await UserModel.findOne({whatsapp})
if(WpCadastrado){
    res.status(400).json({message: 'Whatsapp já cadastrado.'})
return
}


const salt = await bcrypt.genSalt(10)
const hashedpassword = await bcrypt.hash(senha,salt)

const User = new UserModel({
usuario, 
senha:hashedpassword,
email,
whatsapp,
sexo


})
await User.save()

    res.status(200).json({_id: User.id,

        token: userToken(User._id)
 
    
    })
 console.log('enviei')
return
}catch(error){
    res.send(error.message)
}
})




//Cadastrar Empresa
app.post('/cadastroempresa',async (req,res)=>{
  try {
    const {NomeEmpresa, CNPJ, senha,email, whatsapp} = req.body
    if(!NomeEmpresa||!CNPJ||!senha||!email || !whatsapp){
return res.status(400).json({message:"Preencha todos os campos"})
    }

const CNPJcadastrado = await EmpresaModel.findOne({CNPJ})
if(CNPJcadastrado){
return res.status(400).json({message:"Já existe um CNPJ idêntico cadastrado."})
}
const EmailCadastrado = await EmpresaModel.findOne({email})
if(EmailCadastrado){
  return res.status(400).json({message:"já existe um Email idêntico cadastrado."})
}

const wppCadastrado = await EmpresaModel.findOne({whatsapp})
if (wppCadastrado){
  return res.status(400).json({message:'Já existe um Whatsapp idêntico cadastrado.'})
}

const salt = await bcrypt.genSalt(10)
const hashedpassword = await bcrypt.hash(senha,salt)

const Empresa = new EmpresaModel({

  NomeEmpresa, CNPJ, senha:hashedpassword, email,


})
await Empresa.save() 
res.status(200).json({_id:Empresa.id, token: userToken(Empresa._id)})

} catch (error) {
    console.log(error.message)
  }
})



//Login ok!
app.post('/login', async (req, res)=>{

  
 try{

        const {email, senha}= req.body
        if(!email || !senha){
        return res.status(400).json({message: "Algum campo está vazio, por favor, os preencha!"}

        )

}

    const user = await UserModel.findOne({email:email}) 
        if(!user){
            res.status(400).json({message:"Não encontrou o email.Cadastre-se."})
            return
}



    if(user && (await bcrypt.compare(senha,user.senha)))  {
const token = userToken(user._id)


            res.status(200).json({
                token:token, 
                usuario: user.usuario,
                senha:user.senha,
                _id:user.id,
                profissionalNutricao:user.profissionalNutricao,
                profissionalPsicologia:user.profissionalPsicologia,
                profissionalEducacaoFisica:user.profissionalEducacaoFisica,
                profissionalEnfermagem:user.profissionalEnfermagem,
                profissionalFarmaceutico:user.profissionalFarmaceutico,
                profissionalFisioterapeuta:user.profissionalFisioterapeuta,
                
            
         })

         localStorage.setItem('token',token)   

}  




else{
            return res.status(400).json({message:'algum dos campos está errado,tente novamente  '})
}
        res.json({message:`aqui ${user}`})
}catch(error)
{error.message}

}


)

  app.get('/pesquisar-usuarios', async (req, res) => {
    try {
      const termoPesquisa = req.query.q;
      if (termoPesquisa.length < 3) {
        return res.status(400).send('O termo de pesquisa deve ter pelo menos 3 caracteres.');
      }

      const usuariosEncontrados = await UserModel.find(
        { usuario: { $regex: termoPesquisa, $options: 'i' } },
        '_id usuario email'
      );

      if (usuariosEncontrados.length === 0) {
        return res.status(404).send('Nenhum usuário encontrado.');
      }

      const listaUsuarios = usuariosEncontrados.map((usuario) => {
        return { _id: usuario._id, usuario: usuario.usuario, email:usuario.email};
      });

      res.json({ usuarios: listaUsuarios });
    } catch (err) {
      console.error(err);
      res.status(500).send('Erro ao realizar a pesquisa.');
    }
  });




  app.get('/buscar-dieta-admin/:userId', async (req, res) => {
    try {
      const userId = req.params.userId;
      const usuario = await UserModel.findOne({ _id: userId });
      
      if (!usuario) {
        return res.status(404).send('Usuário não encontrado.');
      }
  
      const dieta = usuario.dieta || []; // Se o campo dieta for nulo ou inexistente, retorna um array vazio
  
      res.json({ dieta });
    } catch (error) {
      console.error(error);
      res.status(500).send('Erro ao buscar dieta do usuário.');
    }
  });
  

  



















app.get("/buscar",protect, async (req, res) => {
    try {
      const { usuario } = await UserModel.findById(req.user.id);
  
      res.status(200).json({ usuario:usuario })
    } catch (error) {


      res.status(500).json({message: `aqui ó ${error.message}` })
    }
  })



  app.get("/buscaralimento", async (req, res) => {
    try {
      const { term } = req.query;
      const resultado = await AlimentosModel.findOne({ alimento: term });
  
      if (resultado) {
        res.status(200).json({ alimento: resultado });
      } else {
        res.status(404).json({ message: "Alimento não encontrado" });
      }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  });
  

  app.get('/user/:username', async (req, res) => {
    const { username } = req.params;
    try {
      const user = await UserModel.findOne({ usuario: username });
      if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado.' });
      }
      return res.json(user);
    } catch (error) {
      console.error('Erro ao buscar dados do usuário:', error);
      return res.status(500).json({ message: 'Erro interno do servidor.' });
    }
  });



app.post('/adicionaralimento', async (req,res)=>{
    
    try {
        const {alimento, proteina, carboidrato, lipideo, fibra,
             calcio, magnesio, manganes, fosforo, ferro, sodio,
              potassio, cobre, zinco, vitaminaA, tiamina, riboflavina, 
              piridoxina, niacina, vitaminaC, kilocalorias, indiceGlic, nota
        }= req.body

        if(!alimento){
            return res.status(400).json({message:"nome vazio"})
        }
        if(!proteina){
            return res.status(400).json({message:"proteína vazio"})
        }
        if(!carboidrato){
            return res.status(400).json({message:"carboidrato vazio"})
        }
        if(!lipideo){
            return res.status(400).json({message:"lipideo vazio"})
        }
        if(!fibra){
            return res.status(400).json({message:"fibra vazio"})
        }

        const alimentoCadastrado = await AlimentosModel.findOne({alimento})
        if (alimentoCadastrado){
            return res.status(400).json({message:`O alimento ${alimentoCadastrado} já está cadastrado`})
        }

const Alimentos = new AlimentosModel({
    alimento, proteina, carboidrato, lipideo, fibra,
     calcio, magnesio, manganes, fosforo, ferro,
      sodio, potassio, cobre, zinco, vitaminaA, tiamina, 
      riboflavina, piridoxina, niacina, vitaminaC, kilocalorias, indiceGlic, nota



})

        await Alimentos.save()
       return res.status(200).json({message:`Alimento ${Alimentos.alimento} foi criado com sucesso!`})
    } catch (error) {
        console.error(error);
    return res.status(500).json({ message: 'Ocorreu um erro ao salvar o alimento.' });
 
    }


})


app.get("/buscarxpuser",protect, async (req,res)=>{
try{
const {experiencia} = await UserModel.findById(req.user.id)
const {nivel} = await UserModel.findById(req.user.id)
 res.status(200).json({experiencia:experiencia, nivel:nivel})


}catch(e){
    res.status(500).json({message: `aqui ó ${e.message}` })
}



    
})




app.post("/informacaodieta", protect, async (req, res) => {
    const { atividade, maioria, locomocao, refeicoes } = req.body;
  
    if (!atividade || !maioria || !locomocao || !refeicoes) {
      return res.status(400).json({ message: 'Algum dos campos está faltando.' });
    }
  
    const user = req.user; 
  
    if (!user) {
      return res.status(400).json({ message: 'Usuário não encontrado.' });
    }
  
    try {
      // Atualizar as informações do usuário
      user.atividade = atividade;
      user.maioriaTempo = maioria;
      user.locomocao = locomocao;
      user.refeicoes = refeicoes;
  
      // Salvar as alterações no banco de dados
      await user.save();
  
     return res.status(200).json({ message: `Dados do usuário atualizados: ${user.usuario}` });

    } catch (error) {
      console.log(error.message);
      res.status(500).json({ message: 'Ocorreu um erro ao atualizar os dados do usuário.' });
    }
  });
  



  app.get('/procuraralimento', (req, res) => {
    const query = req.query.query;
  
    AlimentosModel.find({ alimento: { $regex: `^${query}`, $options: 'i' } })
      .then((alimentos) => {
        res.json(alimentos);
      })
      .catch((error) => {
        console.error('Erro ao buscar alimentos:', error);
        res.status(500).json({ error: 'Erro ao buscar alimentos' });
      });
  });

  app.post('/dietauser', async (req, res) => {
    try {
      const { inputs, ...userData } = req.body; // Extrair a informação de inputs do corpo da requisição
      const newUser = new UserModel({ ...userData, dieta: inputs }); // Incluir inputs no campo dieta
      await newUser.save();
      res.status(201).json(newUser);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });



app.put('/atividadefisica/:userId', async(req,res)=>{

  try {
    const { userId } = req.params
    const { atividadeFisica } = req.body;

    const updatedUser = await UserModel.findByIdAndUpdate(
      userId,
      { $set: { atividadeFisica } },
      { new: true }
    );

    console.log('atividadeFisica Atualizada:', JSON.stringify(atividadeFisica, null, 2));
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }

})



app.put('/pesoidadealtura/:userId', async (req,res)=>{

  try {
    const { userId } = req.params
    const {peso, altura,idade } = req.body;

    const updatedUser = await UserModel.findByIdAndUpdate(
      userId,
      { $set: { peso, altura,idade } },
      { new: true }
    );

    console.log('pesoalturaidade Atualizada:', peso+' peso', altura,'altura',idade+ 'idade');
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }





})



app.put('/pescocoquadrilcinturaabdomem/:userId', async (req,res)=>{

  try {
    const { userId } = req.params
    const {circuferenciaAbdomemAtual,circuferenciaCinturaAtual,circuferenciaPescocoAtual,circuferenciaQuadrilAtual } = req.body;

    const updatedUser = await UserModel.findByIdAndUpdate(
      userId,
      { $set: { circuferenciaAbdomemAtual,circuferenciaCinturaAtual,circuferenciaPescocoAtual,circuferenciaQuadrilAtual } },
      { new: true }
    );

    console.log('circuferenciaAbdomemAtual,circuferenciaCinturaAtual,circuferenciaPescocoAtual,circuferenciaQuadrilAtual ', circuferenciaAbdomemAtual,circuferenciaCinturaAtual,circuferenciaPescocoAtual,circuferenciaQuadrilAtual );
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }





})



app.put('/users/:userId/dieta', async (req, res) => {
  try {
    const { userId } = req.params
    const { dieta } = req.body;

    const updatedUser = await UserModel.findByIdAndUpdate(
      userId,
      { $set: { dieta } },
      { new: true }
    );

    console.log('Dieta Atualizada:', JSON.stringify(dieta, null, 2));
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});




app.put('/user/chat/:Id',async (req,res)=>{
  try {
    const { Id } = req.params
    const { chatPaciente } = req.body;

    const updatedChatUser = await UserModel.findByIdAndUpdate(
      Id,
      { $set: { chatPaciente } },
      { new: true }
    );

    console.log('updatedChatUser Atualizada:', updatedChatUser);
    res.json(updatedChatUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
})
  
app.get('/user/chat/:Id', async (req,res)=>{


const userId = req.params.Id
console.log(userId)
const user = await UserModel.findById(userId,'chatPaciente'); // Busque apenas os campos desejados
  
if (user) {
  res.json(user); // Retorna os dados do usuário como JSON
} else {
  res.status(404).json({ message: 'Usuário não encontrado' });
}

})



  app.get('/api/dadosusuario/:Id', async (req, res) => {
    try {
      const userId = req.params.Id; // Obtém o ID do usuário a partir dos parâmetros da URL
      console.log(userId)
      const user = await UserModel.findById(userId, 'peso altura idade sexo circuferenciaAbdomemAtual circuferenciaPescocoAtual circuferenciaQuadrilAtual circuferenciaCinturaAtual usuario'); // Busque apenas os campos desejados
  
      if (user) {
        res.json(user); // Retorna os dados do usuário como JSON
      } else {
        res.status(404).json({ message: 'Usuário não encontrado' });
      }
    } catch (error) {
      console.error('Erro ao buscar dados do usuário:', error);
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  });






  app.put('/inforamocoesFisicas/:Id', async (req,res)=>{

    try{
    const userId = req.params.Id
    
    const usuario = await UserModel.findById(userId);
    
    
    if (!usuario) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }




    
    }catch(e){}
    
    
    
      
    })








 app.put('/dadosfisicosusuario/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    console.log(userId+ "asehuahea hu asueh")
    // Verifique se o usuário com o ID fornecido existe
    const usuario = await UserModel.findById(userId);

    if (!usuario) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // Atualize os campos do usuário com base nos dados fornecidos no corpo da requisição
    
    usuario.peso = req.body.peso;
    usuario.altura = req.body.altura;
    usuario.idade = req.body.idade;
    usuario.circuferenciaAbdomemAtual = req.body.circuferenciaAbdomemAtual;
    usuario.circuferenciaPescocoAtual = req.body.circuferenciaPescocoAtual;
    usuario.circuferenciaQuadrilAtual = req.body.circuferenciaQuadrilAtual;
    usuario.circuferenciaCinturaAtual = req.body.circuferenciaCinturaAtual;
    usuario.sexo = req.body.sexo;

    // Salve as atualizações no banco de dados
    await usuario.save();

    // Responda com uma mensagem de sucesso
    res.status(200).json({ message: 'Dados do usuário atualizados com sucesso.' });
  } catch (error) {
    console.error('Erro ao atualizar os dados do usuário:', error);
    res.status(500).json({ error: 'Ocorreu um erro ao atualizar os dados do usuário.' });
  }
});










app.get('/buscaratividadefisica/:id', async (req,res)=>{

  try {
    
      const userId =req.params.id


      if (!userId || userId === 'undefined') {
        return res.status(400).json({ message: 'ID de usuário inválido' });
      }
  
      const user = await UserModel.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }
  
      res.json({ atividadeFisica: user.atividadeFisica });


  } catch (error) {
    console.error('Erro ao buscar dados da atividadeFisica do usuário:', error);
    res.status(500).json({ message: 'Erro ao buscar dados da atividadeFisica do usuário' });
  }




})








app.get('/atividadefisica/:id', async (req, res) => {
  try {
    const userId = req.params.id;

    if (!userId || userId === 'undefined') {
      return res.status(400).json({ message: 'ID de usuário inválido' });
    }

    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ atividadeFisica: user.atividadeFisica });
  } catch (error) {
    console.error('Erro ao buscar dados da dieta do usuário:', error);
    res.status(500).json({ message: 'Erro ao buscar dados da dieta do usuário' });
  }
});




  app.get('/users/:id/dieta', async (req, res) => {
    try {
      const userId = req.params.id;
  
      if (!userId || userId === 'undefined') {
        return res.status(400).json({ message: 'ID de usuário inválido' });
      }
  
      const user = await UserModel.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }
  
      res.json({ dieta: user.dieta });
    } catch (error) {
      console.error('Erro ao buscar dados da dieta do usuário:', error);
      res.status(500).json({ message: 'Erro ao buscar dados da dieta do usuário' });
    }
  });

app.get("/users/:id/dietamobile", async (req,res)=>{
  try {
    const userId = req.params.id;

    if (!userId || userId === 'undefined') {
      return res.status(400).json({ message: 'ID de usuário inválido' });
    }

    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ dieta: user.dieta });
  } catch (error) {
    console.error('Erro ao buscar dados da dieta do usuário:', error);
    res.status(500).json({ message: 'Erro ao buscar dados da dieta do usuário' });
  }

  

})


app.get('/teste', async (req,res)=>{
  console.log('foi')
  res.json('foi')
})

  
  app.get('/procuraralimento/nutrientes', async (req, res) => {
    const { query } = req.query;
  
    try {
      const alimento = await AlimentosModel.findOne({ alimento: query });
  
      if (!alimento) {
        return res.status(404).json({ message: 'Alimento não encontrado' });
      }
  
      const { proteina, carboidrato, lipideo, kilocalorias,nota } = alimento;
      res.json({ proteina, carboidrato, lipideo, kilocalorias,nota });
    } catch (error) {
      console.error('Erro ao buscar informações de nutrientes do alimento:', error);
      res.status(500).json({ message: 'Erro ao buscar informações de nutrientes do alimento' });
    }
  });


  











const userToken = (id) =>{
    return jwt.sign({id},tokenSecretKey ,{expiresIn: '30d'}
    )}




const connect = require('./mongoConnect')
connect()



app.listen(port,()=>{
    console.log(`listen on ${port}`)
})