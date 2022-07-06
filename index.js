// 백엔드 시작을 하면 이 곳에서 시작을 하게 됨
// npm install express --save 하면 express.js가 다운로드 받아짐

const express = require("express"); // express 모듈을 가져옴
const app = express(); // fuction을 이용하여 새로운 express 모듈을 만듦
const port = 5000; // 포트 설정(아무거나 해도 상관 X)
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const { User } = require("./models/User"); // user.js에서 만든 것
const config = require("./config/key");
const { auth } = require("./middleware/auth");

// application/x-www-form-urlencoded라고 되어 있는 데이터를 분석해서 가져올 수 있게 해줌
app.use(bodyParser.urlencoded({ extended: true }));

// application/json라고 되어 있는 데이터를 분석해서 가져올 수 있게 해줌
app.use(bodyParser.json());
app.use(cookieParser());

const mongoose = require("mongoose");
const { application } = require("express");
mongoose
  .connect(config.mongoURI)
  .then(() => console.log("MongoDB Connected..."))
  .catch((err) => console.log(err));

app.get("/", (req, res) => {
  res.send("Hello World!"); // 루트 디렉토리에 오게 되면 hello world 를 출력하게 함
});

app.post("/api/users/register", (req, res) => {
  // register router
  // 회원가입 할 때 필요한 정보들을 client에서 가져오면
  // 그것을 데이터베이스에 넣어준다.
  const user = new User(req.body); // body에 id, password 등 들어있음(bodyparser 덕분)
  user.save((err, userInfo) => {
    if (err) return res.json({ success: false, err }); // 만약 저장을  했는데 실패했다면 에러 메시지를 띄우고
    return res.status(200).json({
      // 저장을 했는데 성공했다면 success 메시지를 띄움
      success: true,
    });
  });
});

app.post("/api/users/login", (req, res) => {
  User.findOne({ id: req.body.id }, (err, user) => {
    if (!user) {
      return res.json({
        loginSuccess: false,
        message: "회원을 찾을 수 없습니다.",
      });
    }
    // 요청된 이메일이 데이터베이스에 있다면 비밀번호가 맞는 비밀번호인지 확인
    user.comparePassword(req.body.password, (err, isMatch) => {
      if (!isMatch)
        return res.json({
          loginSuccess: false,
          message: "비밀번호가 틀렸습니다.",
        });

      // 비밀번호까지 맞다면 토큰을 생성하기
      user.generateToken((err, user) => {
        if (err) return res.status(400).send(err);

        // 토큰을 저장한다. 어디에? 쿠키, 로컬스토리지, 세션 등 -> 쿠키에 저장함
        res
          .cookie("x_auth", user.token)
          .status(200)
          .json({ loginSuccess: true, userId: req.body.id }); // user._id
      });
    });
  });
});

app.get("/api/users/logout", auth, (req, res) => {
  // console.log('req.user', req.user)
  User.findOneAndUpdate({ _id: req.user._id }, { token: "" }, (err, user) => {
    if (err) return res.json({ success: false, err });
    return res.status(200).send({
      success: true,
      message: "로그아웃 되었습니다.",
    });
  });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`); // 이 앱을 port 5000번에서 실행
});
