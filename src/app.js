const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const routes = require("./routes/routes");
const { errorHandler, notFound } = require("./middleware/errorMiddleware");
const cookieParser = require("cookie-parser");
const passport = require('./config/passport');

const app = express();


const corsOptions = {
  origin: [
    "http://localhost:5173",
    "https://wg.gizmodotech.com",
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["set-cookie"],
  optionsSuccessStatus: 200
};


app.use(cors(corsOptions));


app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
app.use(passport.initialize());

// Routes
app.use("/api", routes);


app.use(notFound);
app.use(errorHandler);

module.exports = app;