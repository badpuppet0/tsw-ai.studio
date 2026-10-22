import { adminAuth } from '../lib/firebase-admin.ts';
import type { DecodedIdToken } from 'firebase-admin/auth';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { getOrCreateUser } from '../db/users.ts';

export interface AuthenticatedUser {
  uid: string;
  email: string;
  dbUserId?: number;
}

export async function verifyAuth(tokenHeader: string | undefined): Promise<AuthenticatedUser | null> {
  if (!tokenHeader) return null;
  const token = tokenHeader.startsWith('Bearer ') ? tokenHeader.slice(7) : tokenHeader;
  if (!token) return null;

  try {
    const decoded: DecodedIdToken = await adminAuth.verifyIdToken(token);
    const dbUser = await getOrCreateUser(decoded.uid, decoded.email || `${decoded.uid}@tswv2.local`);
    return {
      uid: decoded.uid,
      email: decoded.email || '',
      dbUserId: dbUser.id,
    };
  } catch (error) {
    console.error('Firebase token verification failed:', error);
    return null;
  }
}

export async function fastifyAuthMiddleware(request: FastifyRequest, reply: FastifyReply) {
  const authHeader = request.headers.authorization;
  if (!authHeader) {
    reply.code(401).send({ error: 'Unauthorized: Missing authorization header' });
    return;
  }
  const user = await verifyAuth(authHeader);
  if (!user) {
    reply.code(401).send({ error: 'Unauthorized: Invalid or expired token' });
    return;
  }
  (request as any).user = user;
}
