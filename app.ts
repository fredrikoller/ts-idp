import { v4 as uuidv4 } from "uuid";
import { createHash } from "crypto";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import express, { Request, Response } from "express";
import session from "express-session";

interface IUser {
  id: string;
  email: string;
  passwordHash: string;
  salt: string;
}

declare global {
  namespace Express {
    interface User extends IUser {}
  }
}

const users: IUser[] = [];

function generateSalt(): string {
  return uuidv4();
}

function generateHash(password: string, salt: string): string {
  const passwordHash = createHash("sha256")
    .update(password + salt)
    .digest("hex");
  return passwordHash;
}

function validatePassword(
  password: string,
  storedHash: string,
  storedSalt: string
): boolean {
  const passwordHash = createHash("sha256")
    .update(password + storedSalt)
    .digest("hex");
  return passwordHash === storedHash;
}

passport.use(
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    (email, password, done) => {
      const user = users.find((user) => user.email === email);

      if (!user) {
        return done(null, false, { message: "Incorrect credentials" });
      }

      if (!validatePassword(password, user.passwordHash, user.salt)) {
        return done(null, false, {
          message: "The credentials you proivided are incorrect",
        });
      }

      return done(null, user);
    }
  )
);

// Serialisera användaren för sessionen
passport.serializeUser((user: IUser, done) => {
  done(null, user.id);
});

// Deserialisera användaren från sessionen
passport.deserializeUser((id: string, done) => {
  const user = users.find((u) => u.id === id);
  if (!user) {
    return done(new Error("Användare hittades inte"), null);
  }
  done(null, user);
});

const app = express();
const port = 3001;

// Middleware för att hantera POST-förfrågningar och sessioner
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // Set to true if using HTTPS
  })
);
app.use(passport.initialize());
app.use(passport.session());

/*
Routes
*/

app.post("/register", (req: any, res: any) => {
  const { email, password } = req.body;
  if (users.find((user) => user.email === email)) {
    return res.status(400).json({ message: "Email already exists" });
  }

  const salt = generateSalt();
  console.log("Salt:", salt);
  const passwordHash = generateHash(password, salt);
  const newUser: IUser = {
    id: uuidv4(),
    email,
    passwordHash,
    salt,
  };
  users.push(newUser);
  return res.redirect("/login");
});

app.post(
  "/login",
  passport.authenticate("local", {
    // Använd den lokala strategin
    successRedirect: "/dashboard", // Skicka till instrumentpanelen vid lyckad inloggning
    failureRedirect: "/login", // Skicka tillbaka till inloggningssidan vid misslyckad inloggning
    failureMessage: true, // Aktivera felmeddelanden
  })
);

app.get("/dashboard", (req, res) => {
  if (req.isAuthenticated()) {
    res.send(
      `<h1>Välkommen till din instrumentpanel, ${req.user?.email}!</h1><a href="/logout">Logga ut</a>`
    );
  } else {
    res.redirect("/login"); // Skicka till inloggningssidan om inte autentiserad
  }
});

// Enkel sida för registrering
app.get("/register", (req, res) => {
  res.send(`
        <h2>Registrera dig</h2>
        <form method="post" action="/register">
            <label for="username">Användarnamn:</label>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Lösenord:</label>
            <input type="password" id="password" name="password" required><br><br>
            <button type="submit">Registrera</button>
        </form>
        <p>Har du redan ett konto? <a href="/login">Logga in</a></p>
    `);
});

// Enkel sida för inloggning
app.get("/login", (req: any, res: any) => {
  let errorMessage = "";
  if (req.session && req.session.messages) {
    errorMessage = req.session.messages[0] || "";
    req.session.messages = []; // Rensa meddelanden
  }
  res.send(`
        <h2>Logga in</h2>
        <form method="post" action="/login">
            <label for="username">Användarnamn:</label>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Lösenord:</label>
            <input type="password" id="password" name="password" required><br><br>
            <button type="submit">Logga in</button>
        </form>
        <p style="color:red;">${errorMessage}</p>
        <p>Har du inget konto? <a href="/register">Registrera dig</a></p>
    `);
});

// Startsida
app.get("/", (req, res) => {
  res.send(`
      <h1>Välkommen till Identity Provider</h1>
      <p>Detta är en enkel Identity Provider (IDP) för autentisering och auktorisering.</p>
      <ul>
        <li><a href="/register">Registrera dig</a></li>
        <li><a href="/login">Logga in</a></li>
      </ul>
    `);
});

// Starta servern
app.listen(port, () => {
  console.log(`IDP lyssnar på port ${port}`);
});
