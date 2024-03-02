const { MongoClient } = require("mongodb");


const url = "mongodb+srv://metad:CA638iO4500@metad.bs6xu8q.mongodb.net/";
const client = new MongoClient(url);
 

 const dbName = "metad";
              
async function main(){

try{
    await client.connect();
    const db = client.db(dbName);
    console.log("rolou no banco" + db)
    // Reference the "people" collection in the specified database
    const col = db.collection("database");

console.log("rolou no banco")
}catch(e){
    console.log(`erro    h iashdi h hdsa ih ih dj ${e}`)}
}




module.exports =main;