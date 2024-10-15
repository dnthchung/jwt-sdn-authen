const express = require("express");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const path = require("path");

// Load biến môi trường từ file .env
dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Sử dụng cookie-parser

// Cấu hình view engine EJS và thư mục views
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Secret keys từ biến môi trường
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;

// Danh sách refresh token
let refreshTokens = [];

// Danh sách người dùng mẫu
const users = [
  { username: "user1", password: "password1", role: "admin" },
  { username: "user2", password: "password2", role: "user" },
];

// Tạo Access Token có thời hạn 1 phút
function generateAccessToken(user) {
  return jwt.sign(user, accessTokenSecret, { expiresIn: "1m" });
}

// Middleware xác thực Access Token
const authenticateToken = (req, res, next) => {
  const token = req.cookies.accessToken;
  if (!token) return res.redirect("/login");

  jwt.verify(token, accessTokenSecret, (err, user) => {
    if (err) return res.redirect("/refresh"); // Hết hạn, chuyển hướng để làm mới token
    req.user = user;
    next();
  });
};

// Route login: Tách thông báo thành 2 dòng
app.get("/login", (req, res) => {
  res.render("login", {
    usernameHint: "Username: user1",
    passwordHint: "Password: password1",
  });
});

// Xử lý đăng nhập
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) return res.send("Invalid username or password.");

  const accessToken = generateAccessToken({
    username: user.username,
    role: user.role,
  });
  const refreshToken = jwt.sign(
    { username: user.username },
    refreshTokenSecret,
    { expiresIn: "7d" }
  );

  refreshTokens.push(refreshToken);

  res.cookie("accessToken", accessToken, { httpOnly: true });
  res.cookie("refreshToken", refreshToken, { httpOnly: true });
  res.redirect("/home");
});

// Trang Home hiển thị token và thông tin người dùng
app.get("/home", authenticateToken, (req, res) => {
  const accessToken = req.cookies.accessToken;
  const refreshToken = req.cookies.refreshToken;
  res.render("home", { accessToken, refreshToken, users });
});

// Route refresh token
app.get("/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken || !refreshTokens.includes(refreshToken))
    return res.redirect("/login");

  jwt.verify(refreshToken, refreshTokenSecret, (err, user) => {
    if (err) return res.redirect("/login");

    const newAccessToken = generateAccessToken({
      username: user.username,
      role: user.role,
    });
    res.cookie("accessToken", newAccessToken, { httpOnly: true });
    res.redirect("/home"); // Quay lại trang home với token mới
  });
});

// Route logout: Xóa cookie và chuyển hướng về trang login
app.get("/logout", (req, res) => {
  res.clearCookie("accessToken"); // Xóa cookie accessToken
  res.clearCookie("refreshToken"); // Xóa cookie refreshToken
  res.redirect("/login"); // Chuyển hướng về trang login
});

// Khởi động server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
