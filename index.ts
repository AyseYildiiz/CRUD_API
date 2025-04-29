// Install required dependencies before running the code:
// npm init -y
// npm install express knex sqlite3 cors dotenv
// npm install --save-dev typescript ts-node @types/node @types/express
// npx tsc --init

import express from "express";
import cors from "cors";
import knex from "knex";
import { config } from "dotenv";
import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";


config();

// Initialize Knex with SQLitegit
const db = knex({
    client: "sqlite3",
    connection: {
        filename: "./data.sqlite",
    },
    useNullAsDefault: true,
});

// DTO Validations using Zod
const itemSchema = z.object({
    name: z.string().min(1, "Name is required"),
    description: z.string().optional(),
});

// User schema
const userSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(6),
});


// Create a table if not exists
db.schema
    .hasTable("items")
    .then((exists) => {
        if (!exists) {
            return db.schema.createTable("items", (table) => {
                table.increments("id").primary();
                table.string("name").notNullable();
                table.text("description");
            });
        }
    })
    .catch((err) => console.error("Error creating table:", err));

db.schema
    .hasTable("users")
    .then((exists) => {
        if (!exists) {
            return db.schema.createTable("users", (table) => {
                table.increments("id").primary();
                table.string("username").unique().notNullable();
                table.string("password").notNullable();
            });
        }
    })
    .catch((err) => console.error("Error creating table:", err));



const app = express();
app.use(cors());
app.use(express.json());


// Middleware to check if JWT is valid
const authenticateToken = (req: any, res: any, next: any) => {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
        return res.status(401).json({ message: "Access denied, token missing" });
    }

    jwt.verify(token, process.env.JWT_SECRET as string, (err: any, user: any) => {
        if (err) {
            return res.status(403).json({ message: "Invalid token" });
        }

        req.user = user;
        next();
    });
};

// User Registration (Unprotected)
// @ts-ignore
app.post("/register", async (req, res) => {
    const parsed = userSchema.safeParse(req.body);

    if (!parsed.success) {
        return res.status(400).json({ errors: parsed.error.format() });
    }

    const { username, password } = parsed.data;

    // Check if the user already exists
    const userExists = await db("users").where({ username }).first();
    if (userExists) {
        return res.status(400).json({ message: "Username already taken" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the user into the database
    await db("users").insert({ username, password: hashedPassword });

    res.status(201).json({ message: "User registered successfully" });
});

// User Login (Unprotected)
// @ts-ignore
app.post("/login", async (req, res) => {
    const parsed = userSchema.safeParse(req.body);

    if (!parsed.success) {
        return res.status(400).json({ errors: parsed.error.format() });
    }

    const { username, password } = parsed.data;

    // Check if the user exists
    const user = await db("users").where({ username }).first();
    if (!user) {
        return res.status(400).json({ message: "Invalid credentials" });
    }

    // Compare password with the hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.status(400).json({ message: "Invalid credentials" });
    }

    // Create JWT
    const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET as string, { expiresIn: "1h" });

    res.json({ token });
});


// Apply JWT authentication middleware globally to all routes
app.use(authenticateToken);


// CRUD API Routes
app.get("/items", async (req, res) => {
    const items = await db("items").select("*");
    res.json(items);
});

app.get("/items/:id", async (req, res) => {
    const { id } = req.params;
    const item = await db("items").where({ id }).first();
    if (item) {
        res.json(item);
    } else {
        res.status(404).json({ message: "Item not found" });
    }
});

app.get("/users", async (req, res) => {
    const users = await db("users").select("id", "username").orderBy("id","asc");
    res.json(users);
});

// Protected User Profile (Just an example)
app.get("/profile", async (req: any, res) => {
    const userId = req.user.userId;
    // Fetch the user's profile data
    const user = await db("users").where({ id: userId }).first();
    if (user) {
        res.json({ username: user.username });
    } else {
        res.status(404).json({ message: "User not found" });
    }
});

// @ts-ignore
app.post("/items", async (req, res) => {
    const parsed = itemSchema.safeParse(req.body);

    if (!parsed.success) {
        return res.status(400).json({ errors: parsed.error.format() });
    }

    const { name, description } = parsed.data;
    const [id] = await db("items").insert({ name, description });
    res.status(201).json({ id, name, description });
});

// @ts-ignore
app.put("/items/:id", async (req, res) => {
    const { id } = req.params;
    const parsed = itemSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ errors: parsed.error.format() });
    }

    const item = await db("items").where({ id }).first();
    if (!item) {
        return res.status(404).json({ message: "Item not found" });
    }

    const { name, description } = parsed.data;
    await db("items").where({ id }).update({ name, description });
    res.json({ id, name, description });
});

// @ts-ignore
app.delete("/items/:id", async (req, res) => {
    const { id } = req.params;
    const item = await db("items").where({ id }).first();
    if (!item) {
        return res.status(404).json({ message: "Item not found" });
    }

    await db("items").where({ id }).del();
    res.json({ message: "Item deleted" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
