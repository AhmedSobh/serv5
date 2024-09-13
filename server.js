import express from 'express';
import mysql from 'mysql2';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { loginAdmin } from './Controller/adminController.js';  
import { loginUser, registerUser } from './Controller/userController.js';    
//import { RegisterAdmin } from './Controller/adminController.js';

dotenv.config({ path: 'config.env' });

const app = express();
const port = process.env.PORT;
const host = process.env.host;
const user = process.env.user;
const password = process.env.password;
const database = process.env.database;

app.use(bodyParser.json());

export const db = mysql.createConnection({
    host: `${host}`,
    user: `${user}`,
    password: `${password}`,
    database: `${database}`
}).promise();

/** Category Routes **/
app.get('/category', async (req, res) => {
    const { title, details } = req.body;
    try {
        const [rows] = await db.query('SELECT * FROM categories WHERE title = ? OR details = ?', [title, details]);
        res.status(200).json({ data: rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Get category Error' });
    }
});

app.get('/category/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await db.query('SELECT * FROM categories WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Category not found' });
        }
        res.status(200).json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Get category Error' });
    }
});

app.post('/category', async (req, res) => {
    const { title, details } = req.body;
    try {
        const result = await db.query('INSERT INTO categories (title, details) VALUES (?, ?)', [title, details]);
        res.status(201).json(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Add category Error' });
    }
});

/** Product Routes **/
app.get('/product', async (req, res) => {
    const { title, brand, image, details, price } = req.body;
    try {
        const [rows] = await db.query(
            'SELECT * FROM products WHERE title = ? OR brand = ? OR image = ? OR details = ? OR price = ?',
            [title, brand, image, details, price]
        );
        res.status(200).json({ data: rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Get Products Error' });
    }
});

app.get('/product/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await db.query('SELECT * FROM products WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.status(200).json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Get Products Error' });
    }
});

app.post('/product', async (req, res) => {
    const { title, brand, image, details, price } = req.body;
    try {
        const result = await db.query(
            'INSERT INTO products (title, brand, image, details, price) VALUES (?, ?, ?, ?, ?)',
            [title, brand, image, details, price]
        );
        res.status(201).json(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Add Products Error' });
    }
});

app.put('/product/:id', async (req, res) => {
    const { id } = req.params;
    const { title, brand, image, details, price } = req.body;
    try {
        const [result] = await db.query(
            'UPDATE products SET title = ?, brand = ?, image = ?, details = ?, price = ? WHERE id = ?',
            [title, brand, image, details, price, id]
        );
        res.status(200).json({ data: result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Update Products Error' });
    }
});

app.delete('/product/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await db.query('DELETE FROM products WHERE id = ?', [id]);
        res.status(200).json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Delete Products Error' });
    }
});

/** Authentication Routes **/
app.post('/login', async (req, res) => {
    const { username, password, role } = req.body;

    try {
        let query;
        if (role === 'admin') {
            query = 'SELECT * FROM admin WHERE username = ?';
        } else if (role === 'user') {
            query = 'SELECT * FROM user WHERE username = ?';
        } else {
            return res.status(400).json({ message: 'Invalid role' });
        }

        const [rows] = await db.execute(query, [username]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Invalid username' });
        }

        const user = rows[0];

        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username, role }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error logging in' });
    }
});

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token not provided' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

/** Register Routes **/
app.post('/register', registerUser);
app.get('/admin/login', loginAdmin);
app.get('/user/login', loginUser);
//app.post('/admin/register', RegisterAdmin);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
