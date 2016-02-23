var mongoose = require("mongoose");
var bcrypt = require("bcrypt-nodejs");
var Schema = mongoose.Schema;

// USER SCHEMA
var UserSchema = new Schema({
    email: {type: String, unique: true, lowercase: true},
    password: String,
    profile: {
        name: {type: String, default: ""},
        picture: {type: String, default: ""}
    },
    
    address: String,
    history: [{
        date: Date,
        paid: {type: Number, default: 0},
        // item: {type: Schema.Types.ObjectId, ref: ""}
    }]
});

// HASH PASSWORD BEFORE SAVE
UserSchema.pre("save", function(next){
    var user = this;
    if(!user.isModified("password")){
        return next();
    }
    bcrypt.genSalt(10, function(err, salt){
        if(err){
            return next(err);
        }
        bcrypt.hash(user.password, salt, null, function(err, hash){
            if(err){
                return next(err);
            }
            user.password = hash;
            next();
        });
    });
});

// COMPARE DB PASSWORD WITH USER INPUT

UserSchema.methods.comparePassword = function(password){
    return bcrypt.compareSync(password, this.password);
}


// EXPORT FOR APP USE
module.exports = mongoose.model("User", UserSchema);