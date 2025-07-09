const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['Developer', 'ProjectGiver'], required: true },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
