import jwt from "jsonwebtoken";

export function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "missing token" });
  }

  const decoded = jwt.decode(token);
  req.user = decoded;

  return next();
}
