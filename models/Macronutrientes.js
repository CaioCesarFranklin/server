const mongoose = require('mongoose')

const MacronutrientesSchema = new mongoose.Schema({

    proteina:Number,
    carboidrato:Number,
    lipideo:Number,
    fibra:Number
})
const MacronutrientesModel  = mongoose.model('Macronutrientes',MacronutrientesSchema)
