import crypto from 'node:crypto';
import { db } from './index.ts';
import { users, profiles } from './schema.ts';
import { eq, and, desc, sql } from 'drizzle-orm';

const AUTH_SECRET = process.env.AUTH_SECRET || 'tsw-v2-cosmic-auth-secret-key-2026';

export interface ProfileInput {
  name: string;
  avatar?: string;
  themeColor?: string;
  bio?: string;
  shortcuts?: string;
  preferences?: string;
  isDefault?: boolean;
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  try {
    const [salt, key] = storedHash.split(':');
    if (!salt || !key) return false;
    const keyBuffer = Buffer.from(key, 'hex');
    const derivedKey = crypto.scryptSync(password, salt, 64);
    return crypto.timingSafeEqual(keyBuffer, derivedKey);
  } catch {
    return false;
  }
}

export function createSessionToken(userId: number, username: string): string {
  const payload = JSON.stringify({ userId, username, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  const b64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

export function verifySessionToken(token: string): { userId: number; username: string } | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', AUTH_SECRET).update(b64).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return { userId: payload.userId, username: payload.username };
  } catch {
    return null;
  }
}

export async function signUpUser(username: string, password: string, email?: string) {
  const cleanUsername = username.trim();
  if (cleanUsername.length < 3) {
    throw new Error('Username must be at least 3 characters long');
  }
  if (!password || password.length < 4) {
    throw new Error('Password must be at least 4 characters long');
  }

  // Check existing username
  const existing = await db.select().from(users).where(sql`lower(${users.username}) = lower(${cleanUsername})`);
  if (existing.length > 0) {
    throw new Error('Username is already taken. Please choose another.');
  }

  const userEmail = email && email.includes('@') ? email.trim() : `${cleanUsername.toLowerCase()}@tswv2.local`;
  const uid = 'usr_' + crypto.randomBytes(8).toString('hex');
  const passwordHash = hashPassword(password);

  const inserted = await db.insert(users).values({
    uid,
    username: cleanUsername,
    passwordHash,
    email: userEmail,
  }).returning();

  const user = inserted[0];
  if (!user) throw new Error('Failed to create account.');

  // Create initial member profile
  const starterShortcuts = [
    { name: 'TikTok', url: 'https://www.tiktok.com' },
    { name: 'Instagram', url: 'https://www.instagram.com' },
    { name: 'GeForce NOW', url: 'https://play.geforcenow.com' },
    { name: 'Cork7', url: 'https://cork7.com' }
  ];

  const initialProfile = await db.insert(profiles).values({
    userId: user.id,
    name: cleanUsername,
    avatar: 'astronaut',
    themeColor: '#5aa2ff',
    bio: 'Explorer of the cosmos',
    shortcuts: JSON.stringify(starterShortcuts),
    preferences: JSON.stringify({
      searchEngine: 'https://www.google.com/search?q=',
      stars: true,
      shoot: true,
      bg: 'stars'
    }),
    isDefault: true,
  }).returning();

  const token = createSessionToken(user.id, cleanUsername);
  return {
    user: { id: user.id, username: cleanUsername, email: user.email },
    profile: initialProfile[0],
    token,
    isNewAccount: true,
  };
}

export async function loginUser(username: string, password: string) {
  const cleanUsername = username.trim();
  if (!cleanUsername || !password) {
    throw new Error('Username and password are required');
  }

  const existing = await db.select().from(users)
    .where(sql`lower(${users.username}) = lower(${cleanUsername}) OR lower(${users.email}) = lower(${cleanUsername})`);

  if (existing.length === 0 || !existing[0].passwordHash) {
    throw new Error('Invalid username or password');
  }

  const user = existing[0];
  const isValid = verifyPassword(password, user.passwordHash);
  if (!isValid) {
    throw new Error('Invalid username or password');
  }

  const userProfiles = await getUserProfiles(user.id);
  let activeProfile = userProfiles.find(p => p.isDefault) || userProfiles[0];
  if (!activeProfile) {
    activeProfile = await createProfile(user.id, {
      name: user.username || 'Voyager',
      avatar: 'astronaut',
      themeColor: '#5aa2ff',
      bio: 'Explorer of the cosmos',
      isDefault: true
    });
  }

  const token = createSessionToken(user.id, user.username || user.email.split('@')[0]);
  return {
    user: { id: user.id, username: user.username || user.email.split('@')[0], email: user.email },
    profile: activeProfile,
    profiles: userProfiles,
    token,
  };
}

export async function getUserById(userId: number) {
  const res = await db.select({
    id: users.id,
    username: users.username,
    email: users.email,
    createdAt: users.createdAt,
  }).from(users).where(eq(users.id, userId));
  return res[0] || null;
}

export async function getOrCreateUser(uid: string, email: string) {
  try {
    const existing = await db.select().from(users).where(eq(users.uid, uid));
    if (existing.length > 0) {
      return existing[0];
    }

    const inserted = await db.insert(users)
      .values({ uid, email, username: email.split('@')[0] })
      .onConflictDoUpdate({
        target: users.uid,
        set: { email },
      })
      .returning();

    // Create a starter profile for new guest / user
    if (inserted[0]) {
      await db.insert(profiles).values({
        userId: inserted[0].id,
        name: email.split('@')[0] || 'Voyager',
        avatar: 'astronaut',
        themeColor: '#5aa2ff',
        bio: 'Explorer of the cosmos',
        shortcuts: JSON.stringify([
          { name: 'TikTok', url: 'https://www.tiktok.com' },
          { name: 'Instagram', url: 'https://www.instagram.com' },
          { name: 'GeForce NOW', url: 'https://play.geforcenow.com' },
          { name: 'Cork7', url: 'https://cork7.com' }
        ]),
        preferences: JSON.stringify({
          searchEngine: 'https://www.google.com/search?q=',
          stars: true,
          shoot: true,
          bg: 'stars'
        }),
        isDefault: true,
      });
    }

    return inserted[0];
  } catch (error) {
    console.error('Database getOrCreateUser failed:', error);
    throw new Error('Database operation failed.', { cause: error });
  }
}

export async function getUserProfiles(userId: number) {
  try {
    return await db.select().from(profiles).where(eq(profiles.userId, userId)).orderBy(desc(profiles.isDefault), desc(profiles.createdAt));
  } catch (error) {
    console.error('Database getUserProfiles failed:', error);
    throw new Error('Database query failed.', { cause: error });
  }
}

export async function getProfilesByUid(uid: string) {
  try {
    const u = await db.select().from(users).where(eq(users.uid, uid));
    if (!u.length) return [];
    return await db.select().from(profiles).where(eq(profiles.userId, u[0].id)).orderBy(desc(profiles.isDefault), desc(profiles.createdAt));
  } catch (error) {
    console.error('Database getProfilesByUid failed:', error);
    throw new Error('Database query failed.', { cause: error });
  }
}

export async function createProfile(userId: number, data: ProfileInput) {
  try {
    // If set to default, clear other default profiles for this user
    if (data.isDefault) {
      await db.update(profiles)
        .set({ isDefault: false, updatedAt: new Date() })
        .where(eq(profiles.userId, userId));
    }

    const res = await db.insert(profiles).values({
      userId,
      name: data.name.trim(),
      avatar: data.avatar || 'astronaut',
      themeColor: data.themeColor || '#5aa2ff',
      bio: data.bio || '',
      shortcuts: typeof data.shortcuts === 'string' ? data.shortcuts : JSON.stringify(data.shortcuts || []),
      preferences: typeof data.preferences === 'string' ? data.preferences : JSON.stringify(data.preferences || {}),
      isDefault: !!data.isDefault,
    }).returning();

    return res[0];
  } catch (error) {
    console.error('Database createProfile failed:', error);
    throw new Error('Failed to create profile.', { cause: error });
  }
}

export async function updateProfile(profileId: number, userId: number, data: Partial<ProfileInput>) {
  try {
    if (data.isDefault) {
      await db.update(profiles)
        .set({ isDefault: false, updatedAt: new Date() })
        .where(eq(profiles.userId, userId));
    }

    const updateData: Record<string, any> = { updatedAt: new Date() };
    if (data.name !== undefined) updateData.name = data.name.trim();
    if (data.avatar !== undefined) updateData.avatar = data.avatar;
    if (data.themeColor !== undefined) updateData.themeColor = data.themeColor;
    if (data.bio !== undefined) updateData.bio = data.bio;
    if (data.shortcuts !== undefined) {
      updateData.shortcuts = typeof data.shortcuts === 'string' ? data.shortcuts : JSON.stringify(data.shortcuts);
    }
    if (data.preferences !== undefined) {
      updateData.preferences = typeof data.preferences === 'string' ? data.preferences : JSON.stringify(data.preferences);
    }
    if (data.isDefault !== undefined) updateData.isDefault = data.isDefault;

    const res = await db.update(profiles)
      .set(updateData)
      .where(and(eq(profiles.id, profileId), eq(profiles.userId, userId)))
      .returning();

    return res[0];
  } catch (error) {
    console.error('Database updateProfile failed:', error);
    throw new Error('Failed to update profile.', { cause: error });
  }
}

export async function deleteProfile(profileId: number, userId: number) {
  try {
    const res = await db.delete(profiles)
      .where(and(eq(profiles.id, profileId), eq(profiles.userId, userId)))
      .returning();

    return res[0];
  } catch (error) {
    console.error('Database deleteProfile failed:', error);
    throw new Error('Failed to delete profile.', { cause: error });
  }
}
