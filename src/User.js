import mongoose, { Schema } from 'mongoose';
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

User.methods.getView = function getView() {
  const user = this;
  const { name, email } = user;
  return { name, email };
};

export default mongoose.model('User', User);
