import bcrypt from 'bcryptjs';
import mongoose, { Schema } from 'mongoose';
import { PasswordPolicy, charsets } from 'password-sheriff';
import { isEmail } from 'validator';


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

class ValidationError extends Error {
  constructor(...params) {
    super(...params);
    this.name = 'ValidationError';
  }
}

const policy = new PasswordPolicy({
  length: { minLength: 8 },
  identicalChars: {
    max: 2,
  },
  contains: {
    expressions: [
      charsets.lowerCase,
      charsets.upperCase,
      charsets.numbers,
      charsets.specialCharacters,
    ],
  },
});

User.pre('save', function validatePassword(next) {
  const user = this;
  if (!user.isModified('password')) return next();
  if (!policy.check(user.password)) return next(new ValidationError('Invalid Password'));
  return next();
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
