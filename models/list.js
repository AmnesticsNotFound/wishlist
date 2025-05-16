const mongoose = require("mongoose");

const EntrySchema = new mongoose.Schema({
    name: { type:String, required:true, maxLength: 30, },
    //description: {type:String, required:false, maxLength:500},
    //price: { type:String, required:true, maxLength: 10, },
    url: { type:String, required:true, },
    thumbnail: {type:String, required:true,},
    thumbnailURL: {type:String, required:true,},
    timestamp: { type:Date, required: true, default: Date.now}
})

const ListSchema = new mongoose.Schema({
    name: { type:String, required:true, maxLength: 30, },
    description: {type:String, required:false, maxLength:200},
    entries:[{type:EntrySchema, required:false}],
    thumbnail: {type:String, required:true,},
    timestamp: { type:Date, required: true, default: Date.now}
})

module.exports = {List: mongoose.model("List", ListSchema), 
                Entry: mongoose.model("Entry", EntrySchema),
                ListSchema: ListSchema,
                };