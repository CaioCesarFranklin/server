const express = require('express');
const cors = require('cors');
const UserModel = require('./models/User');
const EmpresaModel = require('./models/Empresa');
const AlimentosModel = require('./models/Alimentos');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const Crypto = require('crypto');
const { MongoClient, ObjectId } = require("mongodb");
const moment = require('moment-timezone');
const cron = require('node-cron');
const CryptoJS = require('crypto-js');
// .env
const url = process.env.MONGO;
const ADM = process.env.ADMID;
const chaveSecreta = process.env.CHAVESECRETA;
const secret_key = process.env.SECRET_KEY_data;
const secret_iv =process.env.SECRET_KEY_ivdata
const encryptionMethod = 'AES-256-CBC'
const key = Crypto.createHash('sha512').update( secret_key, 'utf-8').digest('hex').substring(0,32)
const iv = Crypto.createHash('sha512').update( secret_iv, 'utf-8').digest('hex').substring(0,16)
const client = new MongoClient(url);
const database = client.db('metad');
const colecao = database.collection('users');
const AlimentosDB = database.collection('alimentos')




function encrypt_string(plain_text,encryptionMethod,secret,iv){

  var encryptor =Crypto.createCipheriv(encryptionMethod,secret,iv)
  var aes_encrypted= encryptor.update(plain_text,'utf8','base64')+ encryptor.final('base64')
  return Buffer.from(aes_encrypted).toString('base64')
}


function decrypt_string(encryptedMessage,encryptionMethod,secret,iv){
const buff = Buffer.from(  encryptedMessage, 'base64')
encryptedMessage = buff.toString('utf-8')
var decryptor = Crypto.createDecipheriv(encryptionMethod,secret,iv)
return decryptor.update(encryptedMessage,'base64', 'utf8') + decryptor.final('utf8')

}
// var decryptedMessage = decrypt_string('eXlQTWE1UVFBbHhDOFVzcXFUZm1odz09',encryptionMethod,key,iv)
//console.log('aqui o decryp '+ decryptedMessage) // resposta: eXlQTWE1UVFBbHhDOFVzcXFUZm1odz09 



//var encryptedMessage = encrypt_string('hello',encryptionMethod,key,iv)
//console.log('aqui o '+ encryptedMessage) // resposta: dUIrRWVxa2VEaUxGYVJtY28wdlY1UT09 
function getDataAtual() {
  // Obter a data atual no fuso horário de Brasília
  const dataAtual = moment.tz('America/Sao_Paulo');



  
  // Calcular a data de ontem e amanhã
  const dataOntem = dataAtual.clone().subtract(1, 'day');
  const dataAmanha = dataAtual.clone().add(1, 'day');
  const primeiroDiaDoMes = dataAtual.clone().startOf('month');
  const ultimoDiaDoMes = dataAtual.clone().endOf('month');

  // Formatar as datas no formato 'DD/MM/YYYY'
  const formatoData = 'DD/MM/YYYY';

  const dataFormatadaAtual = dataAtual.format(formatoData);


  const dataFormatadaOntem = dataOntem.format(formatoData);

const dataFormatadaPrimeiroDiaDoMes= primeiroDiaDoMes.format(formatoData)
const dataFormatadaUltimoDiaDoMes= ultimoDiaDoMes.format(formatoData)


  console.log(dataFormatadaPrimeiroDiaDoMes +'dataFormatadaPrimeiroDiaDoMes')
  console.log(dataFormatadaUltimoDiaDoMes +'dataFormatadaUltimoDiaDoMes')




  const dataFormatadaAmanha = dataAmanha.format(formatoData);
  

  // Separar os componentes das datas
  let [diaAtual, mesAtual, anoAtual] = dataFormatadaAtual.split('/');
  const [diaOntem, mesOntem, anoOntem] = dataFormatadaOntem.split('/');
  const [diaAmanha, mesAmanha, anoAmanha] = dataFormatadaAmanha.split('/');
  
 
  
  
  




  return {
    dataCompletaAtual: dataFormatadaAtual,
    dataCompletaOntem: dataFormatadaOntem,
    dataCompletaAmanha: dataFormatadaAmanha,
    ultimoDia:dataFormatadaUltimoDiaDoMes,
    primeiroDia:dataFormatadaPrimeiroDiaDoMes,
    diaAtual,
    mesAtual,
    anoAtual,
    diaOntem,
    mesOntem,
    anoOntem,
    diaAmanha,
    mesAmanha,
    anoAmanha
  };
}


function getDaysOfMonth(year, month) {
  const days = [];
  const firstDayOfMonth = new Date(year, month - 1, 1);
  const lastDayOfMonth = new Date(year, month, 0);
  
  for (let i = 1; i <= lastDayOfMonth.getDate(); i++) {
    const day = new Date(year, month - 1, i);
    const diaDoMes = String(day.getDate()).padStart(2, '0');
    const mes = String(day.getMonth() + 1).padStart(2, '0');
    const dataFormatada = `${diaDoMes}/${mes}`;
    days.push(dataFormatada);
  }
 // console.log(days+'uhu');
  return days;
}
// Usando a função para obter as datas
const { ultimoDia,primeiroDia  } = getDataAtual();

console.log("ultimoDia:", ultimoDia);
console.log("primeiroDia:", primeiroDia);


let {  diaOntem,diaAmanha,diaAtual, mesAtual, anoAtual } = getDataAtual();

console.log("Dia:", `${diaAtual}/${mesAtual}`);
console.log("Mês:", mesAtual);
console.log("Ano:", anoAtual);


function getWeek(date) {

  const copiedDate = new Date(date);
  
  // Defina o primeiro dia da semana como domingo (0)
  copiedDate.setHours(0, 0, 0, 0);
  copiedDate.setDate(copiedDate.getDate() + 4 - (copiedDate.getDay() || 7));
  
  // Calcule o número da semana
  const yearStart = new Date(copiedDate.getFullYear(), 0, 1);
  const weekNumber = Math.ceil((((copiedDate - yearStart) / 86400000) + 1) / 7);
  
  return weekNumber;
}

const dataAtual = new Date();
const semanaAtual = getWeek(dataAtual);


    function getDaysOfWeek(year, weekNumber) {
      const days = [];
      const firstDayOfYear = new Date(year, 0, 1);
      const daysOffset = (weekNumber - 1) * 7;
      
      for (let i = 0; i < 7; i++) {
        const day = new Date(firstDayOfYear);
        day.setDate(day.getDate() + i + daysOffset);
        const diaDoMes = String(day.getDate()).padStart(2, '0');
        const mes = String(day.getMonth() + 1).padStart(2, '0');
        const dataFormatada = `${diaDoMes}/${mes}`;
        days.push(dataFormatada);
      }
      console.log(days)
      return days;
    }

// Exemplo de uso:
const dataAtuala = new Date();
const semanaAtuala = getWeek(dataAtual);

const diasDaSemanaAtual = getDaysOfWeek(anoAtual, mesAtual);


const MesDias = getDaysOfMonth(anoAtual, mesAtual); 
MesDias.forEach((data, index) => {
  console.log(`Dia ${index + 1}: ${data}`);
});

function tarefaAoMeioDia() {
  console.log('Tarefa ao meia noite executada.');
  getDataAtual();
}

async function server() {

  const tokenSecretKey = process.env.SECRET_KEY_pass;
  const port = process.env.PORT;

  const dataAtual = getDataAtual();
  const app = express();
  app.use(express.json());
  app.use(cors());




{/* 

  const options = {
    key: fs.readFileSync(keyFile),     // Carrega a chave privada SSL
    cert: fs.readFileSync(certFile)     // Carrega o certificado SSL
  };



  const httpsServer = https.createServer(options, app);


  httpsServer.listen(port, () => {
    console.log(`O servidor está escutando na porta ${port}`);
  });
*/}

  const dadosDaDieta = [
    [
      {
        "idRefeicao": 0,
        "selectValue": "tarde",
        "searchbars": [
          {
            "idAlimento": 0,
            "alimentoEncontrado": "Batata, baroa, cozida",
            "proteina": "0,852083333",
            "carboidrato": "18,94758333",
            "lipideo": "0,166333333",
            "kilocalorias": "80,1197625",
            "nota": "8,2",
            "quantidade": "20",
            "unidadeMedida": "Gramas",
            "fibra": "1,758"
          }
        ]
      },
      {
        "idRefeicao": 1,
        "selectValue": "manha",
        "searchbars": [
          {
            "idAlimento": 0,
            "alimentoEncontrado": "Cebola, crua",
            "proteina": "1,710144928",
            "carboidrato": "8,853188406",
            "lipideo": "0,08",
            "kilocalorias": "39,42004638",
            "nota": "8,7",
            "quantidade": "200",
            "unidadeMedida": "Gramas",
            "fibra": "2,186666667"
          }
        ]
      }
    ]
];



// Exemplo de uso:






function tarefaDiaria( ) {

  getDataAtual();

  console.log('Tarefa diária(00:00) executada.');
  // Adicione aqui a lógica que deseja executar à meia-noite
}

// Agendar a execução da função à meia-noite (00:00)
cron.schedule('0 0 * * *', () => {
  tarefaDiaria();
}, {
  scheduled: true,
  timezone: 'America/Sao_Paulo' // Defina o fuso horário conforme necessário
});

function tarefaMinutoAMinuto() {
  console.log('Tarefa a cada minuto executada.');
  // Adicione aqui a lógica que deseja executar a cada minuto
}





// Agendar a execução da função ao meio-dia todos os dias
cron.schedule('8 0 * * *', () => {
  tarefaAoMeioDia();

}, {
  scheduled: true,
  timezone: 'America/Sao_Paulo' // Defina o fuso horário conforme necessário
});



  // Função para criptografar os dados da dieta
  function criptografarDadosDaDieta(dados, chave) {
      // Converte os dados para uma string JSON
      const dadosString = JSON.stringify(dados);
      
      // Criptografa os dados usando AES e a chave fornecida
      const ciphertext = CryptoJS.AES.encrypt(dadosString, chave).toString();
      
      return ciphertext;
  }
  
  // Função para descriptografar os dados da dieta
  function descriptografarDadosDaDieta(ciphertext, chave) {
      // Descriptografa os dados usando AES e a chave fornecida
      const bytes = CryptoJS.AES.decrypt(ciphertext, chave);
      const dadosString = bytes.toString(CryptoJS.enc.Utf8);
      
      // Converte a string JSON de volta para os dados originais
      const dados = JSON.parse(dadosString);
      
      return dados;
  }
  
 
  
  // Criptografar os dados da dieta
  const dadosCriptografados = criptografarDadosDaDieta(dadosDaDieta, chaveSecreta);
  //console.log('Dados criptografados:', dadosCriptografados);
  
  // Descriptografar os dados da dieta
  const dadosDescriptografados = descriptografarDadosDaDieta(dadosCriptografados, chaveSecreta);
  //console.log('Dados descriptografados:', JSON.stringify(dadosDescriptografados,null,2));






  console.log(JSON. stringify(dataAtual) + ' console.log(dataAtual');





// protect ok! 17/01/24
const protect = async (req,res,next)=>{
  let token
  console.log('daqui')

  if (req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')){

      try {
          //Pegar o token do header
         
          token= req.headers.authorization.split(' ')[1]

          //verificar token
          const decodificar = jwt.verify(token,tokenSecretKey)
          // pegar o user do token
console.log(token)
          req.user = await colecao.findOne({ _id: new ObjectId(decodificar.id) });
          next()
      } catch (error) {

          res.status(401).json({message:`error aqui o  ${error.message} `})

      }
  }else{
    console.log('deu ruim')
  }
}






  try {

    await client.connect();
    console.log('Servidor Online Mestre!')



//Cadastrar ok!- 08/01/24 - 14:01
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



const EmailCrypt =  encrypt_string(email,encryptionMethod,key,iv)
//console.log(EmailCrypt +email )
 const EmailCadastrado = await colecao.findOne({email:EmailCrypt})


 const WppCrypt =  encrypt_string(whatsapp,encryptionMethod,key,iv)
 const  WppCadastrado = await colecao.findOne({whatsapp:WppCrypt})
 //console.log(WppCrypt +whatsapp )

 //console.log(`${EmailAVerificar},${EmailCadastrado} 'aqui'`);





if(EmailCadastrado){
res.status(400).json({message: 'Email já cadastrado.'})
  return
}


if(WppCadastrado){
    res.status(400).json({message: 'Whatsapp já cadastrado.'})
return
}


const hashedpassword = await encrypt_string(senha,encryptionMethod,key,iv)

const hashedEmail = await encrypt_string(email,encryptionMethod,key,iv)
const hashedWpp = await encrypt_string(whatsapp,encryptionMethod,key,iv)

const hashedSexo= await encrypt_string(sexo,encryptionMethod,key,iv)




 

  
const MesDias = getDaysOfMonth(anoAtual, mesAtual); 

//console.log(JSON.stringify(MesDias))




  

const diasDaSemanaAtual = getDaysOfWeek(anoAtual, semanaAtual);
 const diaAtualUtilizavel = { diaAtual } = getDataAtual();
  const dieta = [];

  const informacoesNutricionaisEAtividades = {
    totalKilocalorias: '0.00',
    totalCarboidratos: '0.00',
    totalProteinas: '0.00',
    totalLipideos: '0.00',
    totalFibras: '0.00',
    totalCalcio: '0.00',
    totalMagnesio: '0.00',
    totalManganes: '0.00',
    totalFosforo: '0.00',
    totalFerro: '0.00',
    totalSodio: '0.00',
    totalPotassio: '0.00',
    totalCobre: '0.00',
    totalZinco: '0.00',
    totalVitaminaA: '0.00',
    totalTiamina: '0.00',
    totalRiboflavina: '0.00',
    totalPiridoxina: '0.00',
    totalNiacina: '0.00',
    totalVitaminaC: '0.00',
    totalKcalGastaAtividade:'0.00',
    totalTempoAtividade:'0.00'
  };
  

  const atividadeFisica = [
  ]; 


  const novaDiaeta = {
      
    [`${anoAtual}`]: {
      [`${mesAtual}`]: {}
    }
  };



//console.log(indexDiaAtual+'indexDiaAtual '+ '   '+ diaAtual)
  // Criar objetos apenas para os dias posteriores ao dia atual


  
  for (let i = 0; i < MesDias.length; i++) {
   // console.log('aqui'+ diaAtual)







    novaDiaeta[anoAtual][mesAtual][MesDias[i]] = {
      informacoesNutricionaisEAtividades,
      dieta,
      atividadeFisica,
      medicamento: 'medicamentos'
    };



  }
  //console.log(JSON.stringify(novaDiaeta,null,2))

 
 


  // Criptografar os dados da dieta
  const DiaetaCripto = criptografarDadosDaDieta(novaDiaeta, chaveSecreta);
  //console.log('Dados aara:', DiaetaCripto);


  const User = {
    usuario,
    senha:hashedpassword,
    email:hashedEmail,
    whatsapp:hashedWpp,
    sexo:hashedSexo,
    diaeta:DiaetaCripto
  };

await colecao.insertOne(User);


    res.status(200).json({_id: User.id,

        token: userToken(User._id)
 
    
    })
 console.log('enviei')
return

}catch(error){
    res.send(error.message)
}
})



    

// /users/:id/dieta ok!!
app.get('/users/:id/dieta', async (req, res) => {
  try {
    const userId = req.params.id;
console.log(userId)
    if (!userId || userId === 'undefined') {
      return res.status(400).json({ message: 'ID de usuário inválido' });
    }

    const user = await colecao.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

// Descriptografar os dados da dieta
const dietaDescr = descriptografarDadosDaDieta(user.dieta, chaveSecreta);
console.log('Dados dietaDescr:', JSON.stringify(dadosDescriptografados,null,2));



    res.json({ dieta: dietaDescr });
  } catch (error) {
    console.error('Erro ao buscar dados da dieta do usuário:', error);
    res.status(500).json({ message: 'Erro ao buscar dados da dieta do usuário' });
  }
});

app.get('/users/:id/diaetaDiaria', async (req, res) => {
  try {
    const userId = req.params.id;
console.log(userId)
    if (!userId || userId === 'undefined') {
      return res.status(400).json({ message: 'ID de usuário inválido' });
    }

    const user = await colecao.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

// Descriptografar os dados da dieta
const dietaDescr = descriptografarDadosDaDieta(user.diaeta, chaveSecreta);
//console.log('Dados dietaDescr:', JSON.stringify(dadosDescriptografados,null,2));



    res.json({ diaeta: dietaDescr ,  anoAtual:anoAtual, mes:mesAtual, hoje:`${diaAtual}/${mesAtual}` });
  } catch (error) {
    console.error('Erro ao buscar dados da diaeta do usuário:', error);
    res.status(500).json({ message: 'Erro ao buscar dados da diaeta do usuário' });
  }
});

app.get('/users/:id/informacoesAtividadeNutricao', async (req, res) => {
  try {
    const userId = req.params.id;

    if (!userId || userId === 'undefined') {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    const user = await colecao.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const dietaDescr = descriptografarDadosDaDieta(user.diaeta, chaveSecreta);
    const dadosParaTrabalhar = dietaDescr[anoAtual][mesAtual];
console.log(JSON.stringify(dadosParaTrabalhar,null,2))
    const diaDeOntem = `${diaOntem}/${mesAtual}`;
    const diaDeHoje = `${diaAtual}/${mesAtual}`;
    const diaDeAmanha = `${diaAmanha}/${mesAtual}`;


    console.log(JSON.stringify(dadosParaTrabalhar[diaDeHoje].informacoesNutricionaisEAtividades,null,2))
   const informacoesOntem = dadosParaTrabalhar[diaDeOntem]?.informacoesNutricionaisEAtividades || {};
   const informacoesHoje = dadosParaTrabalhar[diaDeHoje].informacoesNutricionaisEAtividades || {};
    const informacoesAmanha = dadosParaTrabalhar[diaDeAmanha]?.informacoesNutricionaisEAtividades || {};

    console.log(JSON.stringify(informacoesOntem,null,2))
    console.log(JSON.stringify(informacoesHoje,null,2))
    console.log(JSON.stringify(informacoesAmanha,null,2))

res.send({informacoesHoje:informacoesHoje, informacoesAmanha:informacoesAmanha,informacoesOntem:informacoesOntem})

  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: 'Erro ao processar a requisição.' });
  }
});



app.get('/notificationoitomanha',(req,res)=>{
  res.send({message:'uma hora da tarde'})
})




app.get('/testediaeta/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

if(!userId){
  return res.status(404).json({message:'aqui n da '})
}else if(userId){



  const dietateste =  {
    "2024": {
      "04": {
        "01/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "02/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "03/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "04/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "05/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "06/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "07/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "08/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "408800.00",
            "totalCarboidratos": "40000.00",
            "totalProteinas": "7200.00",
            "totalLipideos": "24000.00",
            "totalFibras": "1600.00",
            "totalCalcio": "16000.00",
            "totalMagnesio": "35200.00",
            "totalManganes": "880.00",
            "totalFosforo": "148000.00",
            "totalFerro": "1040.00",
            "totalSodio": "8000.00",
            "totalPotassio": "240000.00",
            "totalCobre": "240.00",
            "totalZinco": "800.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "80.00",
            "totalRiboflavina": "80.00",
            "totalPiridoxina": "80.00",
            "totalNiacina": "640.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [
            {
              "idRefeicao": 0,
              "nomeRefeicao": "Café",
              "selectValue": "manha",
              "searchbars": [
                {
                  "idAlimento": 0,
                  "alimentoEncontrado": "Pasta de Paçoca",
                  "proteina": "9",
                  "carboidrato": "50",
                  "lipideo": "30",
                  "kilocalorias": "511",
                  "nota": "8.7",
                  "quantidade": "80000",
                  "unidadeMedida": "Gramas",
                  "fibra": "2",
                  "calcio": "20",
                  "magnesio": "44",
                  "manganes": "1.1",
                  "fosforo": "185",
                  "ferro": "1.3",
                  "sodio": "10",
                  "potassio": "300",
                  "cobre": "0.3",
                  "zinco": "1",
                  "vitaminaA": "0",
                  "tiamina": "0.1",
                  "riboflavina": "0.1",
                  "piridoxina": "0.1",
                  "niacina": "0.8",
                  "vitaminaC": "0"
                }
              ]
            }
          ],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
   
        "10/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "11/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "12/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "13/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "14/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "15/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "16/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "17/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "18/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "19/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "20/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "21/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "22/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "23/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "24/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "25/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "26/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "27/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "28/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "29/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        },
        "30/04": {
          "informacoesNutricionaisEAtividades": {
            "totalKilocalorias": "0.00",
            "totalCarboidratos": "0.00",
            "totalProteinas": "0.00",
            "totalLipideos": "0.00",
            "totalFibras": "0.00",
            "totalCalcio": "0.00",
            "totalMagnesio": "0.00",
            "totalManganes": "0.00",
            "totalFosforo": "0.00",
            "totalFerro": "0.00",
            "totalSodio": "0.00",
            "totalPotassio": "0.00",
            "totalCobre": "0.00",
            "totalZinco": "0.00",
            "totalVitaminaA": "0.00",
            "totalTiamina": "0.00",
            "totalRiboflavina": "0.00",
            "totalPiridoxina": "0.00",
            "totalNiacina": "0.00",
            "totalVitaminaC": "0.00",
            "totalKcalGastaAtividade": "0.00",
            "totalTempoAtividade": "0.00"
          },
          "dieta": [],
          "atividadeFisica": [],
          "medicamento": "medicamentos"
        }
      }
    }
  }
  

//console.log(JSON.stringify(dadosProntos,null,2))
const dadosCriptografados = criptografarDadosDaDieta(dietateste, chaveSecreta);
const updatedUser = await colecao.findOneAndUpdate(
  { _id: new ObjectId(userId) },
  { $set: { diaeta: dadosCriptografados } },
  { returnDocument: 'after' } // Para retornar o documento atualizado
);


if (!updatedUser) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }
     
      return res.send({dietateste})
    }

 //console.log(dietateste)

    }catch(e){console.log(e)}})

 ///users/:userId/diaetaAmanha ok! 02/04
 app.put('/users/:userId/diaetaAmanha', async (req, res) => {
  try {
    const { userId } = req.params;
    const { diaeta } = req.body;


    const diaAlvo = [`${diaAtual}/${mesAtual}`]
   // console.log(diaAlvo)
    const diaDestino = [`${diaAmanha}/${mesAtual}`]
   // console.log(diaDestino )

    if(!diaeta){  console.log('nao tem diaeta')
  return res.status(404).json({message:"nao tem diaeta"})
  }



    const dadosDeHoje =  diaeta[anoAtual][mesAtual]
    console.log(dadosDeHoje +  'dadosDeHoje')
    const chaveDiaAlvo = Object.keys(dadosDeHoje).find(chave => chave.startsWith(diaAlvo));
    
    console.log(chaveDiaAlvo+  'chaveDiaAlvo')
    const chaveDiaDestino = Object.keys(dadosDeHoje).find(chave => chave.startsWith(diaDestino));


//console.log(JSON.stringify(dadosDeHoje, null, 2));





    if (chaveDiaAlvo && chaveDiaDestino) {
      // Copiar os dados do dia alvo para o dia destino
      dadosDeHoje[chaveDiaDestino] = dadosDeHoje[chaveDiaAlvo];
    //  console.log(JSON.stringify(dadosDeHoje,null,2) );
console.log(chaveDiaAlvo+' chaveDiaAlvo'+ '   '+ chaveDiaDestino+ ' chaveDiaDestino')

      const dadosProntos = {
        [anoAtual]: {
          [mesAtual]: dadosDeHoje
        }
      };



//console.log(JSON.stringify(dadosProntos,null,2))
const dadosCriptografados = criptografarDadosDaDieta(dadosProntos, chaveSecreta);
const updatedUser = await colecao.findOneAndUpdate(
  { _id: new ObjectId(userId) },
  { $set: { diaeta: dadosCriptografados } },
  { returnDocument: 'after' } // Para retornar o documento atualizado
);


if (!updatedUser) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }
     
  

     // res.json(dadosProntos);

    } else if (chaveDiaAlvo &&!chaveDiaDestino){
      // Iterar sobre os dias em MesDias
     

      const diasAusentes = [];
      // Iterar sobre os dias em MesDias
      for (let i = 0; i < MesDias.length; i++) {
      
        const dia = MesDias[i];
        
        // Verificar se o dia está presente em dadosDeHoje
        if (!dadosDeHoje.hasOwnProperty(dia)) {
          
          diasAusentes.push(dia);
        }
  

      }
      
      // Exibir os dias ausentes
      console.log("Dias sem informações:"+diasAusentes);
      
      
      
      for (let i = 0; i < diasAusentes.length; i++) {
        const diaAusente = diasAusentes[i];
      
        // Criar novos dados para o dia ausente
        const novaInformacao = {
          informacoesNutricionaisEAtividades: {
            totalKilocalorias: '0.00',
            totalCarboidratos: '0.00',
            totalProteinas: '0.00',
            totalLipideos: '0.00',
            totalFibras: '0.00',
            totalCalcio: '0.00',
            totalMagnesio: '0.00',
            totalManganes: '0.00',
            totalFosforo: '0.00',
            totalFerro: '0.00',
            totalSodio: '0.00',
            totalPotassio: '0.00',
            totalCobre: '0.00',
            totalZinco: '0.00',
            totalVitaminaA: '0.00',
            totalTiamina: '0.00',
            totalRiboflavina: '0.00',
            totalPiridoxina: '0.00',
            totalNiacina: '0.00',
            totalVitaminaC: '0.00',
            totalKcalGastaAtividade: '0.00',
            totalTempoAtividade: '0.00'
          },
          dieta: [],
          atividadeFisica: [],
          medicamento: 'medicamentos'
        };
      
        // Atribuir os novos dados ao dia ausente em dadosDeHoje
        dadosDeHoje[diaAusente] = novaInformacao;
  
      }
      
      const chaveDiaDestinoAtualizado = Object.keys(dadosDeHoje).find(chave => chave.startsWith(diaDestino));


      dadosDeHoje[chaveDiaDestinoAtualizado] = dadosDeHoje[chaveDiaAlvo];
      console.log(chaveDiaAlvo+'chaveDiaDestino')
      console.log(chaveDiaDestinoAtualizado+ 'chaveDiaDestinoAtualizado')

      const dadosProntos = {
        [anoAtual]: {
          [mesAtual]: dadosDeHoje
        }
      };



//console.log(JSON.stringify(dadosProntos,null,2))
const dadosCriptografados = criptografarDadosDaDieta(dadosProntos, chaveSecreta);
const updatedUser = await colecao.findOneAndUpdate(
  { _id: new ObjectId(userId) },
  { $set: { diaeta: dadosCriptografados } },
  { returnDocument: 'after' } // Para retornar o documento atualizado
);


if (!updatedUser) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }
     


     // console.log(JSON.stringify(dadosDeHoje, null, 2)+  ' e daui sodi io');
      
      
     return   res.json(JSON.stringify('diaeta',null,2)+"aqui o ")
      
      }    else{
      console.log("Não foi possível copiar os dados. Verifique se os dias alvo e destino existem.");
   res.status(404).json({message:' deu rui aqui'})
   
    }



  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



 ///users/:userId/diaetaOntem ok! 02/04
 app.put('/users/:userId/diaetaOntem', async (req, res) => {
  try {
    const { userId } = req.params;
    const { diaeta } = req.body;

   
    const dadosDeHoje =  diaeta[anoAtual][mesAtual]
    const diaAlvo = [`${diaOntem}/${mesAtual}`]
    const diaDestino = [`${diaAtual}/${mesAtual}`]
    
    console.log( diaAlvo +'  '+ diaDestino)


    const chaveDiaAlvo = Object.keys(dadosDeHoje).find(chave => chave.startsWith(diaAlvo));
    const chaveDiaDestino = Object.keys(dadosDeHoje).find(chave => chave.startsWith(diaDestino));

    if (!chaveDiaAlvo) {
      console.log(`Não foi encontrado nenhum dia correspondente a ${diaAlvo}.`);
    
      return res.status(404).json({ error: `Dia ${diaAlvo} não encontrado.` });

    }
    
    
    // Verificar se a chave do dia destino foi encontrada
    if (!chaveDiaDestino) {
      console.log(`Não foi encontrado nenhum dia correspondente a ${diaDestino}.`);
      return res.status(404).json({ error: `Dia ${diaDestino} não encontrado.` });
      
      // Tratar a situação de forma adequada, por exemplo, criar os dados para o dia destino
      // ou enviar uma mensagem de erro para o cliente
    }
    console.log( chaveDiaAlvo +'  '+ chaveDiaDestino+ ' asj ')

    if (chaveDiaAlvo && chaveDiaDestino) {
   
      // Copiar os dados do dia alvo para o dia destino
      dadosDeHoje[chaveDiaDestino] = dadosDeHoje[chaveDiaAlvo];
     
     
      const dadosProntos = {
        [anoAtual]: {
          [mesAtual]: dadosDeHoje
        }
      };
     
     
     
  

//console.log(JSON.stringify(dadosProntos,null,2))
const dadosCriptografados = criptografarDadosDaDieta(dadosProntos, chaveSecreta);
const updatedUser = await colecao.findOneAndUpdate(
  { _id: new ObjectId(userId) },
  { $set: { diaeta: dadosCriptografados } },
  { returnDocument: 'after' } // Para retornar o documento atualizado
);
      if (!updatedUser) {
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }

     // console.log('Dieta Atualizada criptografada:', JSON.stringify(dadosCriptografados, null, 2));
      //console.log('Dieta Atualizada:', JSON.stringify(diaeta, null, 2));
      res.json(diaeta);



    } else {
      console.log("Não foi possível copiar os dados. Verifique se os dias alvo e destino existem.");
    }

  
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/users/:userId/diaetaDiaria', async (req, res) => {
  try {
    const { userId } = req.params;
    const { diaeta } = req.body;

     console.log(JSON.stringify(diaeta,null ,2))
    

     const dadosCriptografados = criptografarDadosDaDieta(diaeta, chaveSecreta);


     const updatedUser = await colecao.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $set: { diaeta: dadosCriptografados } },
      { returnDocument: 'after' } // Para retornar o documento atualizado
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

  res.json(diaeta);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});




app.get('/users/:id/pesoalturaidade', async (req, res) => {
  try {
    const userId = req.params.id;
//console.log(userId)
    if (!userId || userId === 'undefined') {
      return res.status(400).json({ message: 'ID de usuário inválido' });
    }

    const user = await colecao.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
//console.log(user)
// Descriptografar os dados da dieta

var dietaDescrSexo = decrypt_string(user.sexo,encryptionMethod,key,iv)
if(user.peso && user.altura && user.idade){

  var dietaDescrSexo = decrypt_string(user.sexo,encryptionMethod,key,iv)
  var dietaDescrPeso = decrypt_string(user.peso,encryptionMethod,key,iv)
  var dietaDescrAltura = decrypt_string(user.altura,encryptionMethod,key,iv)
  var dietaDescrIdade = decrypt_string(user.idade,encryptionMethod,key,iv)
}else{console.log('nao há dados de peso, altura e idade')
return}

if (!dietaDescrPeso || !dietaDescrAltura || !dietaDescrIdade) {
  return res.status(404).json({ message: 'Valores de peso, altura ou idade não encontrados para este usuário' });
}

console.log(dietaDescrPeso+'  ' + dietaDescrAltura+ '  '+ dietaDescrIdade+ '   '+ dietaDescrSexo)

    res.json({ peso: dietaDescrPeso ,  altura:dietaDescrAltura, idade:dietaDescrIdade,sexo:dietaDescrSexo });
  } catch (error) {
    //console.log('Erro ao buscar dados da diaeta do usuário:', error);
    res.status(500).json({ message: 'Erro ao buscar dados da diaeta do usuário' });
  }
});



app.post('/cadastrodiaeta',async(req,res)=>{
  try{

console.log('oi')
res.send({ message: 'oi' }); 




return



  }catch(e){console.log(e.message)}


})




//Cadastrar Empresa NAOOK!
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
const hashedemail = await bcrypt.hash(email,salt)
const hashedempresa = await bcrypt.hash(NomeEmpresa,salt)
const hashedCNPJ = await bcrypt.hash(CNPJ,salt)

const Empresa = new EmpresaModel({

  NomeEmpresa:hashedempresa, CNPJ:hashedCNPJ, senha:hashedpassword, email:hashedemail,


})
await Empresa.save() 
res.status(200).json({_id:Empresa.id, token: userToken(Empresa._id)})

} catch (error) {
    console.log(error.message)
  }
})



//Login ok! - 29/01/24 -14:32
app.post('/login', async (req, res)=>{

  
 try{

        const {email, senha}= req.body
        if(!email || !senha){
        return res.status(400).json({message: "Algum campo está vazio, por favor, os preencha!"}

        )

}

const EmailCrypt =  encrypt_string(email,encryptionMethod,key,iv)

    const user = await colecao.findOne({email:EmailCrypt})
  
        if(!user){
            res.status(400).json({message:"Não encontrou o email.Cadastre-se."})
            return
}


function CheckValues(value1, value2) {
  return value1 === value2;
}


const senhadECRIPT= await decrypt_string(user.senha,encryptionMethod,key,iv)

let resultado = CheckValues(senhadECRIPT, senha);


    if(user && ( resultado))  {
  
const token = userToken(user._id)

const sexodencript= await decrypt_string(user.sexo,encryptionMethod,key,iv)
            res.status(200).json({
                token:token, 
                usuario: user.usuario,
                senha:user.senha,
                _id:user._id,
                sexo:sexodencript,
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
// exemplo
app.get('/search', async (req,res)=>{
  try {


    let result = await colecao.aggregate([
      {
      "$search":{
        "autocomplete":{

          "query":`${req.query.term}`,
          "path": "usuario",
          
        }


      }
    }]).toArray()
    console.log(result)
    res.send(result)




  } catch (error) {
    res.status(500).send({message: error.message})
  }
})

// pesquisar usuario ok! 14/01/24
  app.get('/pesquisar-usuarios', async (req, res) => {
    try {


      let result = await colecao.aggregate([
        {
        "$search":{
          "autocomplete":{
  
            "query":`${req.query.term}`,
            "path": "usuario",
            
          }
  
  
        }
      }]).toArray()
      console.log(result)
      res.send(result)
  
  
  
  
    } catch (error) {
      res.status(500).send({message: error.message})
    }
  });



  

 


  // buscaralimento ok! 17/01/24
  app.get("/buscaralimento/:alimento", async (req, res) => {
    const { alimento } = req.params;
    try {


      let result = await AlimentosDB.aggregate([
        {
          $search: {
            "index": "alimentos",
            "text": {
              "path": "alimento",
              "query": alimento,
              "fuzzy": {}
            }
          }
        },
        {
          $sort: {
            "score": { "$meta": "textScore" }
          }
        }
      ]).toArray();
      console.log(result)
      res.send(result)
  
  
  
  
    } catch (error) {
      res.status(500).send({message: error.message})
    }

{/*

    try {
      const { term } = req.query;
      const resultado = await AlimentosDB.findOne({ alimento: term });
  console.log(resultado)
      if (resultado) {
        res.status(200).json({ alimento: resultado });
      } else {
        res.status(404).json({ message: "Alimento não encontrado" });
      }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
 */}
  });
  
  // /user/:username ok! 17/01/24
  app.get('/user/:username', async (req, res) => {
    const { username } = req.params;
    try {
      const user = await colecao.findOne({ usuario: username });
      if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado.' });
      }
      return res.json(user);
    } catch (error) {
      console.error('Erro ao buscar dados do usuário:', error);
      return res.status(500).json({ message: 'Erro interno do servidor.' });
    }
  });


//   adicionar Alimento ok! 15-01-24
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

        const alimentoCadastrado = await AlimentosDB.findOne({alimento})
        if (alimentoCadastrado){
            return res.status(400).json({message:`O alimento ${alimentoCadastrado} já está cadastrado`})
        }


        const Alimentos = {
          alimento, proteina, carboidrato, lipideo, fibra,
          calcio, magnesio, manganes, fosforo, ferro,
           sodio, potassio, cobre, zinco, vitaminaA, tiamina, 
           riboflavina, piridoxina, niacina, vitaminaC, kilocalorias, indiceGlic, nota
        };
      
      await AlimentosDB.insertOne(Alimentos);



       return res.status(200).json({message:`Alimento ${Alimentos.alimento} foi criado com sucesso!`})
    } catch (error) {
        console.error(error);
    return res.status(500).json({ message: 'Ocorreu um erro ao salvar o alimento.' });
 
    }


})


// buscar ok! 17-01-24
app.get("/buscar", protect, async (req, res) => {
  try {
    const { usuario } = await colecao.findOne({ _id: new ObjectId(req.user._id) });
    res.status(200).json({ usuario });
  } catch (error) {
    res.status(500).json({ message: `Erro ao buscar usuário: ${error.message}` });
  }
});



 ///buscarxpuser ok! 26/01/24
app.get("/buscarxpuser",protect, async (req,res)=>{
try{
const {experiencia} = await colecao.findOne({ _id: new ObjectId(req.user._id) });
const {nivel} = await colecao.findOne({ _id: new ObjectId(req.user._id) });
 res.status(200).json({experiencia:experiencia, nivel:nivel})


}catch(e){
    res.status(500).json({message: `aqui ó ${e.message}` })
}



    
})



 ///  /informacaodieta NAO ok! 17/01/24
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
  


// procuraralimento ok! 17/01/24
app.get('/procuraralimento', async (req, res) => {
  const query = req.query.query;

  try {
      let result = await AlimentosDB.aggregate([
          {
              $search: {
                  "index": "alimentos",
                  "text": {
                      "path": "alimento",
                      "query": query,
                      "fuzzy": {}
                  }
              }
          },
          {
              $sort: {
                  "score": { "$meta": "textScore" }
              }
          },
          {
              $limit: 10 // Limite para 10 resultados, por exemplo
          }
      ]).toArray();

      //console.log(result);
      res.send(result);
  } catch (error) {
      res.status(500).send({message: error.message});
  }
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

// put /atividadefisica/ ok! 28/01/24

app.put('/atividadefisica/:userId', async(req,res)=>{

  try {
    const { userId } = req.params
    const { atividadeFisica } = req.body;

    const updatedUser = await colecao.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $set: { atividadeFisica: atividadeFisica } },
      { returnDocument: 'after' } // Para retornar o documento atualizado
    );

    console.log('atividadeFisica Atualizada:', JSON.stringify(atividadeFisica, null, 2));
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }

})


// put /pesoalturaidade/ ok !! 28/01/24
app.put('/pesoidadealtura/:userId', async (req,res)=>{

  try {
    const { userId } = req.params
    const {peso, altura,idade } = req.body;


var encryptedPeso = encrypt_string(peso,encryptionMethod,key,iv)
//console.log('aqui o '+ encryptedMessage) // resposta: dUIrRWVxa2VEaUxGYVJtY28wdlY1UT09 

var encryptedALTURA = encrypt_string(altura,encryptionMethod,key,iv)
//console.log('aqui o '+ encryptedMessage) // resposta: dUIrRWVxa2VEaUxGYVJtY28wdlY1UT09 


var encryptedIdade = encrypt_string(idade,encryptionMethod,key,iv)
//console.log('aqui o '+ encryptedMessage) // resposta: dUIrRWVxa2VEaUxGYVJtY28wdlY1UT09 
    const updatedUser = await colecao.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $set: { peso: encryptedPeso, altura:encryptedALTURA, idade:encryptedIdade } },
      { returnDocument: 'after' } // Para retornar o documento atualizado
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


var encryptedCircuferenciaAbdomemAtual = encrypt_string(circuferenciaAbdomemAtual,encryptionMethod,key,iv)
//console.log('aqui o '+ encryptedMessage) 
var encryptedCircuferenciaCinturaAtual = encrypt_string(circuferenciaCinturaAtual,encryptionMethod,key,iv)
//console.log('aqui o '+ encryptedMessage) 

var encryptedCircuferenciaPescocoAtual = encrypt_string(circuferenciaPescocoAtual,encryptionMethod,key,iv)
//console.log('aqui o '+ encryptedMessage) 


var encryptedCircuferenciaQuadrilAtual = encrypt_string(circuferenciaQuadrilAtual,encryptionMethod,key,iv)
//console.log('aqui o '+ encryptedMessage) 
    
    const updatedUser = await colecao.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $set: { circuferenciaAbdomemAtual: encryptedCircuferenciaAbdomemAtual, circuferenciaCinturaAtual:encryptedCircuferenciaCinturaAtual, circuferenciaPescocoAtual:encryptedCircuferenciaPescocoAtual,circuferenciaQuadrilAtual:encryptedCircuferenciaQuadrilAtual } },
      { returnDocument: 'after' } // Para retornar o documento atualizado
    );




    console.log('circuferenciaAbdomemAtual,circuferenciaCinturaAtual,circuferenciaPescocoAtual,circuferenciaQuadrilAtual ', circuferenciaAbdomemAtual,circuferenciaCinturaAtual,circuferenciaPescocoAtual,circuferenciaQuadrilAtual );
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }





})

  // buscar-dieta-admin ok!!
  app.get('/buscar-dieta-admin/:userId', async (req, res) => {
    const { userId } = req.params;
    console.log(userId);
  
    try {
      let result = await colecao.findOne({ _id: new ObjectId(userId) });
  
      if (!result) {
        return res.status(404).send('Usuário não encontrado.');
      }
  
      const dieta = result.dieta || [];
  
      res.json({ dieta });
    } catch (error) {
      console.error(error);
      res.status(500).send('Erro ao buscar dieta do usuário.');
    }
  });


 ///users/:userId/dieta ok! 27/01
app.put('/users/:userId/dieta', async (req, res) => {
  try {
    const { userId } = req.params;
    const { dieta } = req.body;

    const dadosCriptografados = criptografarDadosDaDieta(dieta, chaveSecreta);
    console.log('Dados criptografados:dieta', dadosCriptografados);
    


    const updatedUser = await colecao.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $set: { dieta: dadosCriptografados } },
      { returnDocument: 'after' } // Para retornar o documento atualizado
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    console.log('Dieta Atualizada:', JSON.stringify(dadosCriptografados, null, 2));
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});











// put user/chat/:Id ok 27/01/24
app.put('/user/chat/:Id',async (req,res)=>{
  try {
    const { Id } = req.params
    const { chatPaciente } = req.body;

    const updatedChatUser = await colecao.findOneAndUpdate(
      { _id: new ObjectId(Id) },
      { $set: { chatPaciente } },
      { returnDocument: 'after' } // Para retornar o documento atualizado
    );

    console.log('updatedChatUser Atualizada:', updatedChatUser);
    res.json(updatedChatUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
})
  

// get user/chat ok ! 27/01/24
app.get('/user/chat/:userId', async (req, res) => {
  try {
    const userId = req.params.userId; // Use 'userId' em vez de 'Id'
    console.log(userId);

    const user = await colecao.findOne({ _id: new ObjectId(userId) });

    if (user) {
      res.json(user.chatPaciente); // Retorna os dados do usuário como JSON
    } else {
      res.status(404).json({ message: 'Usuário não encontrado' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});





// get /atividadefisica/:id ok! 27/01/24
app.get('/atividadefisica/:id', async (req, res) => {
  try {
    const userId = req.params.id;

    if (!userId || userId === 'undefined') {
      return res.status(400).json({ message: 'ID de usuário inválido' });
    }

    const user = await colecao.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const dadosDescriptografados = descriptografarDadosDaDieta(user.atividadeFisica, chaveSecreta);
    //console.log('Dados descriptografados:', JSON.stringify(dadosDescriptografados,null,2));
  


    res.json({ atividadeFisica: dadosDescriptografados });
  } catch (error) {
    console.error('Erro ao buscar dados da dieta do usuário:', error);
    res.status(500).json({ message: 'Erro ao buscar dados da dieta do usuário' });
  }
});











//  /api/dadosusuario/:Id ok !  27/01/24
  app.get('/api/dadosusuario/:Id', async (req, res) => {
    try {
      const userId = req.params.Id; // Obtém o ID do usuário a partir dos parâmetros da URL

      const user = await colecao.findOne({ _id: new ObjectId(userId) });
   
      if (user) {
        const dadosDescriptografados = descriptografarDadosDaDieta(user.atividadeFisica, chaveSecreta);

        res.json(dadosDescriptografados)
       
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









// /buscaratividadefisica/ ok! 28/01/24
app.get('/buscaratividadefisica/:id', async (req,res)=>{

  try {
    
      const userId =req.params.id


      if (!userId || userId === 'undefined') {
        return res.status(400).json({ message: 'ID de usuário inválido' });
      }
  
      const user = await colecao.findOne({ _id: new ObjectId(userId) });
      if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }
  
      res.json({ atividadeFisica: user.atividadeFisica });


  } catch (error) {
    console.error('Erro ao buscar dados da atividadeFisica do usuário:', error);
    res.status(500).json({ message: 'Erro ao buscar dados da atividadeFisica do usuário' });
  }




})













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
  
      const { proteina, carboidrato, lipideo, kilocalorias,nota,sodio } = alimento;
      res.json({ proteina, carboidrato, lipideo, kilocalorias,nota,sodio });
    } catch (error) {
      console.error('Erro ao buscar informações de nutrientes do alimento:', error);
      res.status(500).json({ message: 'Erro ao buscar informações de nutrientes do alimento' });
    }
  });


  











const userToken = (id) =>{
    return jwt.sign({id},tokenSecretKey ,{expiresIn: '30d'}
    )}

    app.listen(port, () => {
      console.log(`O servidor está escutando na porta ${port}`);
    });
  } catch (error) {
    console.error(`Erro ao iniciar o servidor: ${error.message}`);
  }
}

server(); 