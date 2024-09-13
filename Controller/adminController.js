import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { db } from '../server.js';

const secret = process.env.JWT_SECRET;

export const getAdmins = (username) => {
    return db.query('SELECT * FROM register WHERE username = ?', [username]);
};
/*export const RegisterAdmin = async (req, res) => {
    const { username, password } = req.body;

    try {
        const hashedPassword = bcrypt.hashSync(password, 10);

        const result = await db.query('INSERT INTO register (username, password) VALUES (?, ?)', 
                                      [username, hashedPassword]);

        res.status(201).json({ message: 'Admin registered successfully', data: result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error registering admin' });
    }
};*/
export const loginAdmin = async (req, res) => {
    const { username, password } = req.body;
    try {
        const [admins] = await getAdmins(username);
        if (admins.length === 0) {
            return res.status(401).json({ message: 'Invalid username' });
        }

        const admin = admins[0];
        if (!bcrypt.compareSync(password, admin.password)) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: admin.id, role: 'admin' }, secret, { expiresIn: '3h' });
        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error' });
    }
};
