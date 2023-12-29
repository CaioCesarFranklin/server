const mongoose = require('mongoose')


const AlimentosSchema =new mongoose.Schema({

    
    alimento: { type: String, required: true },
    kilocalorias: {type:String},
    proteina: { type: String, required: true },
    carboidrato: { type: String, required: true },
    lipideo: { type: String, required: true },
    fibra: { type: String, required: true },
    calcio: { type: String },
    magnesio: { type: String },
    manganes: { type: String },
    fosforo: { type: String },
    ferro: { type: String },
    sodio: { type: String },
    potassio: { type: String },
    cobre: { type: String },
    zinco: { type: String },
    vitaminaA: { type: String },
    tiamina: { type: String },
    riboflavina: { type: String },
    piridoxina: { type: String },
    niacina: { type: String },
    vitaminaC: { type: String },
    indiceGlic:{ type: String },
    nota:{type: String}
    
})

AlimentosModel = mongoose.model('Alimentos',AlimentosSchema)
module.exports = AlimentosModel


