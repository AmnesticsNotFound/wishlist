const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
    email: { type:String, required:true, maxLength: 30, },
    
})

module.exports = mongoose.model("User", UserSchema);;
                