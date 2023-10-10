import jwt from 'jsonwebtoken';

export default (req, res, next) => {
    const token = req.headers['x-auth-token'];

    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' })
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        console.log(req.user);
        next();
    } catch (error) {
        return res.status(401).json({ msg: "Token is invalid" })
    }
}