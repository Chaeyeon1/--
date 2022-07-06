const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");

const userSchema = mongoose.Schema({
  name: {
    type: String,
    minlength: 2,
    maxlength: 4,
  },
  id: {
    type: String,
    unique: 1,
  },
  email: {
    type: String,
    trim: true, // 띄어쓰기를 없애주는 역할
    unique: 1, // 중복 X
  },
  password: {
    type: String,
    minlength: 9,
    // maxlength: 12,
  },
  num: {
    type: String,
    unique: 1,
  },
  nick: {
    type: String,
    unique: 1,
  },
  role: {
    type: Number, // 관리자 지정 (0이면 유저, 1이면 관리자)
    default: 0,
  },
  image: String,
  token: {
    type: String, // 유효성 관리
  },
  tokenExp: {
    type: Number,
  },
});

userSchema.pre("save", function (next) {
  // save하기 전에 무엇을 해주어라 -> 다 끝나면 next function으로 next로 보냄
  var user = this;

  if (user.isModified("password")) {
    // 비밀번호를 암호화 시킨다.
    bcrypt.genSalt(saltRounds, function (err, salt) {
      if (err) return next(err); // 만약, 에러가 있다면 next에서 err로 이동

      bcrypt.hash(user.password, salt, function (err, hash) {
        // error가 없다면 password에 대해서 hash를 해줌
        if (err) return next(err); // 여기에서도 error가 있다면 error 처리를 해줌
        user.password = hash; // 없으면 password를 hash
        next();
      });
    });
  } else {
    next();
  }
});

userSchema.methods.comparePassword = function (plainPassword, cb) {
  // 암호화 되어있는 것을 복호화 하는 것은 불가능, plainPassword를 가져와서 이것을 암호화 한 후 비교 해야 함
  bcrypt.compare(plainPassword, this.password, function (err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

userSchema.methods.generateToken = function (cb) {
  var user = this;

  // jsonwebtoken을 이용해서 token을 생성하기
  var token = jwt.sign(user._id.toHexString(), "secretToken");

  user.token = token;
  user.save(function (err, user) {
    if (err) return cb(err);
    cb(null, user);
  });
};

userSchema.statics.findByToken = function (token, cb) {
  var user = this;

  // 토큰을 decode 한다.
  jwt.verify(token, "secretToken", function (err, decoded) {
    // 유저 아이디를 이용해서 유저를 찾은 다음에
    // 클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인

    user.findOne({ _id: decoded, token: token }, function (err, user) {
      if (err) return cb(err);
      cb(null, user);
    });
  });
};

const User = mongoose.model("User", userSchema); // model로 감싸줌

module.exports = { User };
