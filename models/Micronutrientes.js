const mongoose = require('mongoose')

const MicronutrientesSchema = new mongoose.Schema({

    calcio: Number,
    magnesio: Number,
    manganes: Number,
    fosforo: Number,
    ferro: Number,
    sodio: Number,
    potassio: Number,
    cobre: Number,
    zinco: Number,
    vitaminaA: Number,
    tiamina: Number,
    riboflavina: Number,
    piridoxina: Number,
    niacina: Number,
    vitaminaC: Number
})
const MicronutrientesModel = mongoose.model('Micronutrientes',MicronutrientesSchema)
