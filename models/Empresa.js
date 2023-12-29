const mongoose = require('mongoose')
const Schema = mongoose.Schema
const EmpresaSchema = new mongoose.Schema({
    NomeEmpresa:{ type: String, required: true, unique:true},
    CNPJ:{ type: Number, required: true, unique: true},
    senha:{type: String, required:true},
    email:{ type:String, required:true, unique:true},
    metacoins:{ type: Number},
    nivel:{type:Number, default:1},
    apoiador:{ type: String, enum:['Sim','Nao'],default:"Nao"},
    User:[{type: Schema.Types.ObjectId, ref:"User"}]

})
EmpresaModel= mongoose.model('Empresa',EmpresaSchema)
module.exports = EmpresaModel