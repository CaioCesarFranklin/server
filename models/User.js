
const mongoose = require('mongoose')
const Schema = mongoose.Schema

const UserSchema = new mongoose.Schema({


usuario:{type:String, required:true, unique: true},

sexo:{type:String},
peso:{type:String},
altura:{type:String},
idade:{type:String},

circuferenciaAbdomemAtual:{type:String},
circuferenciaQuadrilAtual:{type:String},
circuferenciaPescocoAtual:{type:String},
circuferenciaCinturaAtual:{type:String},


senha:{type:String, required:true},

email:{type:String, required:true,  unique:true},

whatsapp:{type:Number, required:true,  unique:true},

metacoins:{type:Number,default:1 },

nivel:{type:Number, default:1},

experiencia:{type:Number, default:0},
//rotina
atividade: {
    type: String,
    enum: ['manha', 'tarde', 'noite'],
  
  },
maioria:{
    type:String,
    enum:['deitado','sentado', 'em pe', 'movimentando']
},
locomocao:{
    type:String,
    enum:['caminhando','veiculo automotor','veiculo nao motorizado','home office']
},

pacientes: [{ type: Schema.Types.ObjectId, ref: 'Paciente' }],
empresa:[{type: Schema.Types.ObjectId, ref:'Empresa'}],
apoiador:{ type: String, enum:['Sim','Nao'],default:"Nao"},
profissionalNutricao:{ type: String, enum:['Sim','Nao'],default:"Nao"},
profissionalPsicologia:{ type: String, enum:['Sim','Nao'],default:"Nao"},
profissionalEducacaoFisica:{ type: String, enum:['Sim','Nao'],default:"Nao"},
profissionalEnfermagem:{ type: String, enum:['Sim','Nao'],default:"Nao"},
profissionalDentista:{ type: String, enum:['Sim','Nao'],default:"Nao"},
profissionalFarmaceutico:{ type: String, enum:['Sim','Nao'],default:"Nao"},
profissionalFisioterapeuta:{ type: String, enum:['Sim','Nao'],default:"Nao"},


dieta:{type:Array, default:[]},


atividadeFisica:{type:Array, default:[]},


chatPaciente:{type:Array,default:[{"mensagem": "Bem-vindo!", "user": "Nutri"}]}


})

UserModel = mongoose.model('User',UserSchema)

module.exports = UserModel