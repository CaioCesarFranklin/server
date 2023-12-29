const mongoose= require('mongoose')



async function main(){

try{
await mongoose.connect('mongodb://127.0.0.1:27017/metad')
console.log("rolou no banco")
}catch(e){
    console.log(`erro    h iashdi h hdsa ih ih dj ${e}`)}
}




module.exports =main;