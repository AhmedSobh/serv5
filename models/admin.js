import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { getAdmins } from '../models/admin.js';

const secret = process.env.JWT_SECRET;

export const loginAdmin = async (req, res) => {
    const { username, password } = req.body;

    try {
        const [admins] = await getAdmins(username);
        if (admins.length === 0) {
            return res.status(401).json({ message: 'Invalid username' });
        }

        const admin = admins[0];

        const isMatch = bcrypt.compareSync(password, admin.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: admin.id, role: admin.role }, secret, { expiresIn: '2h' });
        res.json({ token });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server Error' });
    }
};
