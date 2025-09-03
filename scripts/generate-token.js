import 'dotenv/config';
import jwt from 'jsonwebtoken';

const { JWT_SECRET, JWT_ISSUER = 'qdrant-collection-proxy', QDRANT_COLLECTION_NAME } = process.env;

if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET in environment');
  process.exit(1);
}

const [,, sub = 'client', expires = '1h'] = process.argv;

const token = jwt.sign(
  {
    sub,
    scope: 'read',
    col: QDRANT_COLLECTION_NAME,
  },
  JWT_SECRET,
  {
    issuer: JWT_ISSUER,
    expiresIn: expires,
  }
);

console.log(token);
