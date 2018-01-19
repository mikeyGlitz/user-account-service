import mongoose, { Schema } from 'mongoose';
import { isEmail } from 'validator';
import bcrypt from 'bcryptjs';


const User = new Schema({
  name: {
    first: { type: String, required: true },
    last: { type: String, required: true },
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: isEmail,
    },
  },
  password: { type: String, required: true },
});

const SALT_FACTOR = 12;

User.pre('save', function encryptPassword(next) {
  const user = this;
  if (!user.isModified('password')) return next();
  return bcrypt.genSalt(SALT_FACTOR)
    .then(salt => bcrypt.hash(user.password, salt))
    .then((hash) => {
      user.password = hash;
      next();
    });
});

User.methods.comparePasswords = function comparePasswords(candidatePassword) {
  const user = this;
  return bcrypt.compareSync(candidatePassword, user.password);
};

User.methods.getView = function getView() {
  const user = this;
  const { name, email } = user;
  return { name, email };
};

export default mongoose.model('User', User);
