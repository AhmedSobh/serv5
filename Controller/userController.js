import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { db } from '../server.js';

const secret = process.env.JWT_SECRET;

export const getUser = (username) => {
    return db.query('SELECT * FROM register WHERE username = ?', [username]);
};

export const registerUser = async (req, res) => {
    const { username, password, role } = req.body;

    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = await db.query('INSERT INTO register (username, password, role) VALUES (?, ?, ?)', 
                                      [username, hashedPassword, role]);

        res.status(201).json({ message: 'User registered successfully', data: result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error registering user' });
    }
};

export const loginUser = async (req, res) => {
    const { username, password } = req.body;
    try {
        const [users] = await getUser(username);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid username' });
        }

        const user = users[0];
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: '3h' });
        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error' });
    }
};
