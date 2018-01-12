import User from './User';

const registerUser = (req, resp) => {
  const { user } = req.body;
  if (!user) return resp.sendStatus(400);
  return User.create(user)
    .then((result) => {
      resp.status(200).json(result.getView());
    })
    .catch((err) => {
      if (err.code === 11000) return resp.sendStatus(401);
      if (err.name === 'ValidationError') return resp.sendStatus(400);
      return resp.sendStatus(500);
    });
};

const loginUser = (req, resp) => {
  const { email, password } = req.body;
  if (!email) return resp.sendStatus(401);
  if (!password) return resp.sendStatus(401);
  return User.findOne({ email })
    .then((result) => {
      if (!result) return resp.sendStatus(404);
      if (!result.comparePasswords(password)) return resp.sendStatus(401);
      return resp.status(200).json(result.getView());
    })
    .catch(() => resp.sendStatus(500));
};

export { registerUser, loginUser };
