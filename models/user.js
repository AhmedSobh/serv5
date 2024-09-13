import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { getUser } from '../models/user.js';

const secret = process.env.JWT_SECRET;

export const loginUser = async (req, res) => {
    const { username, password } = req.body;

    try {
        const [users] = await getUser(username);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid username' });
        }

        const user = users[0];

        console.log('Password from database:', user.password);
        console.log('Password entered:', password);

        const isMatch = bcrypt.compareSync(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: '3h' });
        res.json({ token });

    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ message: 'Server Error' });
    }
};
