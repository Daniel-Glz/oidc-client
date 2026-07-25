import express from "express";
import session from "express-session";
import { authRouter } from "./routes/auth.js";

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET!,
    resave: false,
    saveUninitialized: false,
}))

app.use("/auth", authRouter);

app.get("/", (req, res) => {
  if (req.session.user) {
    res.send(`<pre>${JSON.stringify(req.session.user, null, 2)}</pre>
      <a href="/auth/logout">Logout</a>`);
  } else {
    res.send(`<a href="/auth/login">Login con Auth0</a>`);
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`Server is running on port ${process.env.PORT || 3000}`);
});