import mockingoose from 'mockingoose';
import casual from 'casual';
import bcrypt from 'bcryptjs';

import { registerUser, loginUser } from '../src/UserHandler';


const lowerCase = () => casual.random_element('abcdefghijklmnopqrstuvwxyz'.split(''));
const upperCase = () => casual.random_element('abcdefghijklmnopqrstuvwxyz'
  .toUpperCase()
  .split(''));
const integer = () => casual.integer(0, 9);
const specialCharacter = () => casual.random_element(' !"#$%&\'`()[]+-,./\\@;:=<>~|?_'
  .split(''));
const anyCharacter = () =>
  casual.random_element([lowerCase(), upperCase(), integer(), specialCharacter()]);

casual.define('securePassword', () => {
  const length = casual.integer(15, 25);
  const pw = [lowerCase(), upperCase(), integer(), specialCharacter()];
  while (pw.length < length) {
    pw.push(anyCharacter());
  }

  return pw.join('');
});

casual.define('user', () => ({
  name: {
    first: casual.first_name,
    last: casual.last_name,
  },
  password: casual.securePassword,
  email: casual.email,
}));

class DuplicateError extends Error {
  constructor(...params) {
    super(...params);
    this.code = 11000;
  }
}

describe('UserHandler', () => {
  beforeEach(() => mockingoose.resetAll());

  describe('#registerUser', () => {
    it('Rejects a user whose password isn\'t log enough', (done) => {
      const reqUser = casual.user;
      reqUser.password = 'aaaaa';

      const req = { body: { user: reqUser } };

      const sendStatus = jest.fn();
      const status = jest.fn();
      const json = jest.fn();
      status.mockImplementation(() => ({ json }));

      const resp = { status, sendStatus };

      registerUser(req, resp)
        .then(() => {
          expect(sendStatus.mock.calls[0][0]).toEqual(400);
          done();
        });
    });

    it('Rejects a user whose password doesn\'t match requirements', (done) => {
      const reqUser = casual.user;
      reqUser.password = 'abcd123457810112';

      const req = { body: { user: reqUser } };

      const sendStatus = jest.fn();
      const status = jest.fn();
      const json = jest.fn();
      status.mockImplementation(() => ({ json }));

      const resp = { status, sendStatus };

      registerUser(req, resp)
        .then(() => {
          expect(sendStatus.mock.calls[0][0]).toEqual(400);
          done();
        });
    });

    it('Rejects a user that is already registered', (done) => {
      const reqUser = casual.user;

      const req = { body: { user: reqUser } };

      const sendStatus = jest.fn();
      const status = jest.fn();
      const json = jest.fn();
      status.mockImplementation(() => ({ json }));

      const resp = { status, sendStatus };

      mockingoose.User.toReturn(new DuplicateError(), 'save');

      registerUser(req, resp)
        .then(() => {
          expect(sendStatus.mock.calls[0][0]).toEqual(401);
          done();
        });
    });

    it('Registers a valid user', (done) => {
      const reqUser = casual.user;

      const req = { body: { user: reqUser } };

      const sendStatus = jest.fn();
      const status = jest.fn();
      const json = jest.fn();
      status.mockImplementation(() => ({ json }));

      const resp = { status, sendStatus };

      mockingoose.User.toReturn({ id: casual.uuid, ...reqUser });

      registerUser(req, resp)
        .then(() => {
          expect(status.mock.calls[0][0]).toEqual(200);
          done();
        });
    });
  });

  describe('#loginUser', () => {
    it('Rejects a user that doesn\'t exist', (done) => {
      const req = { body: { email: casual.email, password: casual.password } };

      const sendStatus = jest.fn();
      const status = jest.fn();
      const json = jest.fn();
      status.mockImplementation(() => ({ json }));

      const resp = { status, sendStatus };

      mockingoose.User.toReturn(null, 'findOne');
      loginUser(req, resp)
        .then(() => {
          expect(sendStatus.mock.calls[0][0]).toEqual(404);
          done();
        });
    });

    it('Rejects a user with an invalid password', (done) => {
      const req = { body: { email: casual.email, password: casual.password } };

      const sendStatus = jest.fn();
      const status = jest.fn();
      const json = jest.fn();
      status.mockImplementation(() => ({ json }));

      const resp = { status, sendStatus };

      const dbUser = casual.user;
      mockingoose.User.toReturn(dbUser, 'findOne');
      loginUser(req, resp)
        .then(() => {
          expect(sendStatus.mock.calls[0][0]).toEqual(401);
          done();
        });
    });

    it('Logs in a valid user', (done) => {
      /* eslint-disable prefer-destructuring */
      const password = casual.password;
      /* eslint-enable */
      const req = { body: { email: casual.email, password } };

      const sendStatus = jest.fn();
      const status = jest.fn();
      const json = jest.fn();
      status.mockImplementation(() => ({ json }));

      const resp = { status, sendStatus };

      const salt = bcrypt.genSaltSync(12);
      const dbUser = casual.user;
      dbUser.password = bcrypt.hashSync(password, salt);

      mockingoose.User.toReturn(dbUser, 'findOne');
      loginUser(req, resp)
        .then(() => {
          expect(status.mock.calls[0][0]).toEqual(200);
          done();
        });
    });
  });
});
