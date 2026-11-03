import crypto from 'node:crypto';
import { db } from './index.ts';
import { users, profiles, friends, messages, publicMessages } from './schema.ts';
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

export const VALID_ROLES = [
  'owner',
  'admin',
  'moderator',
  'VIP',
  'Discord Member',
  'Tester',
  'Beta User',
  'TSW User'
];

export function parseRoles(roleStr?: string | null): string[] {
  if (!roleStr) return ['TSW User'];
  const parts = roleStr.split(',').map(s => s.trim()).filter(Boolean);
  if (parts.length === 0) return ['TSW User'];
  const normalized = parts.map(p => {
    const matched = VALID_ROLES.find(r => r.toLowerCase() === p.toLowerCase());
    return matched || p;
  });
  return Array.from(new Set(normalized));
}

export function userHasRole(user: { id?: number; username?: string | null; email?: string | null; role?: string | null } | null | undefined, targetRole: string): boolean {
  if (!user) return false;
  const target = targetRole.toLowerCase().trim();
  if (target === 'owner' && isUserAdmin(user)) return true;
  const roles = parseRoles(user.role);
  return roles.some(r => r.toLowerCase() === target);
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
  const isOwner = cleanUsername.toLowerCase() === 'alex dalbey' || userEmail.toLowerCase() === 'alexc.second@gmail.com';
  const role = isOwner ? 'owner' : 'TSW User';

  const inserted = await db.insert(users).values({
    uid,
    username: cleanUsername,
    passwordHash,
    email: userEmail,
    role,
  }).returning();

  const user = inserted[0];
  if (!user) throw new Error('Failed to create account.');

  const starterShortcuts = [
    { name: 'YouTube', url: 'https://www.youtube.com' },
    { name: 'TikTok', url: 'https://www.tiktok.com' },
    { name: 'Geforce Now', url: 'https://play.geforcenow.com' },
    { name: 'Roblox', url: 'https://www.roblox.com' },
    { name: 'Twitch', url: 'https://www.twitch.tv' },
    { name: 'Snapchat', url: 'https://www.snapchat.com' },
    { name: 'Instagram', url: 'https://www.instagram.com' },
    { name: 'Discord', url: 'https://discord.com/app' },
    { name: 'GTA 5', url: 'gta5://options' },
    { name: 'Movies', url: 'https://sflix.to' }
  ];

  const initialProfile = await db.insert(profiles).values({
    userId: user.id,
    name: cleanUsername,
    avatar: isOwner ? 'crown' : 'astronaut',
    themeColor: '#5aa2ff',
    bio: isOwner ? 'TSW Creator & Owner' : 'Explorer of the cosmos',
    shortcuts: JSON.stringify(starterShortcuts),
    preferences: JSON.stringify({
      searchEngine: 'https://www.google.com/search?q=',
      stars: true,
      shoot: false,
      bg: 'stars'
    }),
    isDefault: true,
  }).returning();

  const token = createSessionToken(user.id, cleanUsername);
  return {
    user: { id: user.id, username: cleanUsername, email: user.email, role: user.role || role, roles: parseRoles(user.role || role) },
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

  // Ensure role is accurate if logging in as Alex Dalbey
  if ((user.username?.toLowerCase() === 'alex dalbey' || user.email?.toLowerCase() === 'alexc.second@gmail.com') && !parseRoles(user.role).includes('owner')) {
    const newRoleStr = user.role && user.role !== 'TSW User' ? `owner, ${user.role}` : 'owner';
    await db.update(users).set({ role: newRoleStr }).where(eq(users.id, user.id));
    user.role = newRoleStr;
  }

  const userProfiles = await getUserProfiles(user.id);
  let activeProfile = userProfiles.find(p => p.isDefault) || userProfiles[0];
  if (!activeProfile) {
    activeProfile = await createProfile(user.id, {
      name: user.username || 'Voyager',
      avatar: userHasRole(user, 'owner') ? 'crown' : 'astronaut',
      themeColor: '#5aa2ff',
      bio: userHasRole(user, 'owner') ? 'TSW Creator & Owner' : 'Explorer of the cosmos',
      isDefault: true
    });
  }

  const token = createSessionToken(user.id, user.username || user.email.split('@')[0]);
  return {
    user: { id: user.id, username: user.username || user.email.split('@')[0], email: user.email, role: user.role || 'TSW User', roles: parseRoles(user.role) },
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
    role: users.role,
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

    const isOwner = email.toLowerCase() === 'alexc.second@gmail.com';
    const role = isOwner ? 'owner' : 'TSW User';

    const inserted = await db.insert(users)
      .values({ uid, email, username: email.split('@')[0], role })
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
          { name: 'YouTube', url: 'https://www.youtube.com' },
          { name: 'TikTok', url: 'https://www.tiktok.com' },
          { name: 'Geforce Now', url: 'https://play.geforcenow.com' },
          { name: 'Roblox', url: 'https://www.roblox.com' },
          { name: 'Twitch', url: 'https://www.twitch.tv' },
          { name: 'Snapchat', url: 'https://www.snapchat.com' },
          { name: 'Instagram', url: 'https://www.instagram.com' },
          { name: 'Discord', url: 'https://discord.com/app' },
          { name: 'GTA 5', url: 'gta5://options' },
          { name: 'Movies', url: 'https://sflix.to' }
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

export async function ensureChatTables() {
  // Schema managed via Drizzle & Cloud SQL
  return;
}

export async function searchUsers(searchTerm: string, currentUserId: number) {
  await ensureChatTables();
  const term = searchTerm.trim().toLowerCase();
  if (!term) return [];
  const results = await db.select({
    id: users.id,
    username: users.username,
  }).from(users).where(sql`lower(${users.username}) LIKE ${'%' + term + '%'} AND ${users.id} != ${currentUserId} AND (password_hash IS NOT NULL OR email = 'alexc.second@gmail.com') AND email NOT LIKE '%@scramjet.local' AND email NOT LIKE '%@guest.tswv2.local' AND uid NOT LIKE 'guest_%' AND uid NOT LIKE 'system_%'`).limit(10);

  const friendRows = await db.select().from(friends).where(eq(friends.userId, currentUserId));
  const friendIds = new Set(friendRows.map(f => f.friendId));

  return results.map(u => ({
    id: u.id,
    username: u.username || 'User',
    isFriend: friendIds.has(u.id),
  }));
}

const PROFANITY_LIST = [
  'fuck', 'shit', 'bitch', 'asshole', 'cunt', 'dick', 'pussy', 'whore', 'slut',
  'fag', 'faggot', 'nigger', 'nigga', 'retard', 'cock', 'bastard', 'nazi', 'hitler'
];

export function filterProfanity(text: string): string {
  if (!text) return '';
  let res = text;
  for (const word of PROFANITY_LIST) {
    const regex = new RegExp(`\\b${word}\\b|\\b${word}s\\b|\\b${word}ing\\b|\\b${word}ed\\b`, 'gi');
    res = res.replace(regex, (match) => '*'.repeat(match.length));
  }
  return res;
}

export async function addFriend(userId: number, targetUsername: string) {
  await ensureChatTables();
  const cleanTarget = targetUsername.trim().replace(/^@/, '');
  const targetUserRows = await db.select().from(users).where(sql`lower(${users.username}) = lower(${cleanTarget})`);
  if (targetUserRows.length === 0) {
    throw new Error(`User "@${cleanTarget}" not found`);
  }
  const targetUser = targetUserRows[0];
  if (targetUser.id === userId) {
    throw new Error('You cannot add yourself as a friend');
  }

  // Check if existing friendship or request exists
  const existingRows = await db.select().from(friends).where(
    sql`(${friends.userId} = ${userId} AND ${friends.friendId} = ${targetUser.id}) OR (${friends.userId} = ${targetUser.id} AND ${friends.friendId} = ${userId})`
  );

  const existingFromMe = existingRows.find(r => r.userId === userId);
  const existingToMe = existingRows.find(r => r.userId === targetUser.id);

  if (existingFromMe && existingFromMe.status === 'accepted') {
    return {
      id: targetUser.id,
      friendId: targetUser.id,
      username: targetUser.username,
      status: 'accepted',
      isPending: false,
      message: `You are already friends with @${targetUser.username}!`,
    };
  }

  // If the target already sent us a request, approve it automatically!
  if (existingToMe && existingToMe.status === 'pending') {
    await db.execute(sql`
      INSERT INTO friends (user_id, friend_id, status)
      VALUES (${userId}, ${targetUser.id}, 'accepted')
      ON CONFLICT (user_id, friend_id) DO UPDATE SET status = 'accepted';
    `);
    await db.execute(sql`
      INSERT INTO friends (user_id, friend_id, status)
      VALUES (${targetUser.id}, ${userId}, 'accepted')
      ON CONFLICT (user_id, friend_id) DO UPDATE SET status = 'accepted';
    `);
    return {
      id: targetUser.id,
      friendId: targetUser.id,
      username: targetUser.username,
      status: 'accepted',
      isPending: false,
      message: `Accepted mutual friend request with @${targetUser.username}!`,
    };
  }

  // Otherwise create a pending friend request requiring their approval
  await db.execute(sql`
    INSERT INTO friends (user_id, friend_id, status)
    VALUES (${userId}, ${targetUser.id}, 'pending')
    ON CONFLICT (user_id, friend_id) DO UPDATE SET status = 'pending';
  `);

  return {
    id: targetUser.id,
    friendId: targetUser.id,
    username: targetUser.username,
    status: 'pending',
    isPending: true,
    message: `Friend request sent to @${targetUser.username}. Awaiting approval!`,
  };
}

export async function getIncomingFriendRequests(userId: number) {
  await ensureChatTables();
  const res = await db.execute(sql`
    SELECT f.id, f.user_id as "requesterId", u.username, f.created_at as "createdAt"
    FROM friends f
    JOIN users u ON u.id = f.user_id
    WHERE f.friend_id = ${userId} AND f.status = 'pending'
    ORDER BY f.created_at DESC;
  `);

  return (res.rows || []).map((r: any) => ({
    id: r.id,
    requesterId: r.requesterId,
    username: r.username || 'User',
    createdAt: r.createdAt,
  }));
}

export async function acceptFriendRequest(userId: number, requesterId: number) {
  await ensureChatTables();
  if (!Number.isInteger(userId) || !Number.isInteger(requesterId) || userId <= 0 || requesterId <= 0 || userId === requesterId) {
    throw new Error('Invalid friend request.');
  }

  // Use PostgreSQL directly so acceptance works with the existing directional
  // friends rows and the unique index already present in Cloud SQL.
  const accepted = await db.execute(sql`
    UPDATE friends
    SET status = 'accepted'
    WHERE user_id = ${requesterId}
      AND friend_id = ${userId}
      AND status = 'pending'
    RETURNING id;
  `);
  const acceptedRows = accepted.rows || [];
  if (acceptedRows.length === 0) {
    const existing = await db.execute(sql`
      SELECT status FROM friends
      WHERE user_id = ${requesterId} AND friend_id = ${userId}
      LIMIT 1;
    `);
    if (!existing.rows?.length || (existing.rows[0] as any).status !== 'accepted') {
      throw new Error('This friend request is no longer pending. Refresh your requests and try again.');
    }
  }

  await db.execute(sql`
    INSERT INTO friends (user_id, friend_id, status)
    VALUES (${userId}, ${requesterId}, 'accepted')
    ON CONFLICT (user_id, friend_id) DO UPDATE SET status = 'accepted';
  `);

  const reqUser = await getUserById(requesterId);
  if (!reqUser) throw new Error('The requesting account could not be found.');
  return { success: true, friend: reqUser };
}

export async function declineFriendRequest(userId: number, requesterId: number) {
  await ensureChatTables();
  await db.delete(friends).where(
    sql`${friends.userId} = ${requesterId} AND ${friends.friendId} = ${userId} AND ${friends.status} = 'pending'`
  );
  return { success: true };
}

export async function removeFriend(userId: number, friendId: number) {
  await ensureChatTables();
  await db.delete(friends).where(
    sql`(${friends.userId} = ${userId} AND ${friends.friendId} = ${friendId}) OR (${friends.userId} = ${friendId} AND ${friends.friendId} = ${userId})`
  );
  return { success: true };
}

export async function getFriendsList(userId: number) {
  await ensureChatTables();
  const res = await db.execute(sql`
    SELECT u.id, u.username,
      COALESCE(p.avatar, 'astronaut') as avatar,
      (
        SELECT content FROM messages
        WHERE (sender_id = ${userId} AND receiver_id = u.id)
           OR (sender_id = u.id AND receiver_id = ${userId})
        ORDER BY created_at DESC LIMIT 1
      ) as "lastMessage",
      (
        SELECT created_at FROM messages
        WHERE (sender_id = ${userId} AND receiver_id = u.id)
           OR (sender_id = u.id AND receiver_id = ${userId})
        ORDER BY created_at DESC LIMIT 1
      ) as "lastMessageTime",
      (
        SELECT count(*)::int FROM messages
        WHERE sender_id = u.id AND receiver_id = ${userId} AND is_read = false
      ) as "unreadCount"
    FROM friends f
    JOIN users u ON u.id = f.friend_id
    LEFT JOIN profiles p ON p.user_id = u.id AND p.is_default = true
    WHERE f.user_id = ${userId} AND f.status = 'accepted'
    ORDER BY "unreadCount" DESC, "lastMessageTime" DESC NULLS LAST, u.username ASC
  `);

  return (res.rows || []).map((r: any) => ({
    id: r.id,
    friendId: r.id,
    username: r.username,
    avatar: r.avatar || 'astronaut',
    isOnline: true,
    online: true,
    lastMessage: r.lastMessage || null,
    lastMessageTime: r.lastMessageTime || null,
    unreadCount: Number(r.unreadCount || 0),
    unread: Number(r.unreadCount || 0) > 0,
  }));
}

export async function getUnreadNotifications(userId: number) {
  await ensureChatTables();
  const res = await db.execute(sql`
    SELECT count(*)::int as "count", sender_id as "senderId"
    FROM messages
    WHERE receiver_id = ${userId} AND is_read = false
    GROUP BY sender_id;
  `);

  let totalUnread = 0;
  const bySender: Record<number, number> = {};
  (res.rows || []).forEach((row: any) => {
    const c = Number(row.count || 0);
    totalUnread += c;
    bySender[Number(row.senderId)] = c;
  });

  return { totalUnread, bySender };
}

export async function getDirectMessages(userId: number, friendId: number) {
  await ensureChatTables();
  // Mark incoming messages from friend as read
  await db.update(messages)
    .set({ isRead: true })
    .where(and(eq(messages.senderId, friendId), eq(messages.receiverId, userId), eq(messages.isRead, false)));

  const rows = await db.select().from(messages).where(
    sql`(${messages.senderId} = ${userId} AND ${messages.receiverId} = ${friendId}) OR (${messages.senderId} = ${friendId} AND ${messages.receiverId} = ${userId})`
  ).orderBy(messages.createdAt);

  return rows.map(m => ({
    id: m.id,
    senderId: m.senderId,
    receiverId: m.receiverId,
    content: m.content,
    isRead: m.isRead,
    createdAt: m.createdAt,
    isMe: m.senderId === userId,
  }));
}

export async function sendDirectMessage(senderId: number, receiverId: number, content: string) {
  const moderation = await getUserModerationState(senderId);
  if (moderation.banned) throw new Error('Your account is banned from TSW chat.');
  if (moderation.dmTimeoutUntil && new Date(moderation.dmTimeoutUntil).getTime() > Date.now()) {
    throw new Error('You are timed out from direct messages until ' + new Date(moderation.dmTimeoutUntil).toLocaleString());
  }
  await ensureChatTables();
  const clean = filterProfanity(content.trim());
  if (!clean) throw new Error('Message content cannot be empty');

  const rec = await getUserById(receiverId);
  if (!rec) throw new Error('Recipient user not found');

  const inserted = await db.insert(messages).values({
    senderId,
    receiverId,
    content: clean,
  }).returning();

  const msg = inserted[0];
  return {
    id: msg.id,
    senderId: msg.senderId,
    receiverId: msg.receiverId,
    content: msg.content,
    createdAt: msg.createdAt,
    isMe: true,
  };
}

export async function deleteDirectMessage(userId: number, messageId: number) {
  await ensureChatTables();
  await db.delete(messages).where(
    and(eq(messages.id, messageId), eq(messages.senderId, userId))
  );
  return { success: true };
}

export async function editDirectMessage(userId: number, messageId: number, content: string) {
  await ensureChatTables();
  const clean = filterProfanity(content.trim());
  if (!clean) throw new Error('Content cannot be empty');
  await db.update(messages).set({ content: clean }).where(
    and(eq(messages.id, messageId), eq(messages.senderId, userId))
  );
  return { success: true, content: clean };
}

export async function getOrCreateGuestUser(clientId: string, preferredName: string = 'Guest') {
  await ensureChatTables();
  const guestUid = `guest_${clientId.slice(0, 32)}`;
  const existing = await db.select().from(users).where(eq(users.uid, guestUid)).limit(1);
  if (existing.length > 0) {
    return existing[0];
  }
  const cleanName = preferredName.replace(/[^a-zA-Z0-9_ -]/g, '').trim().slice(0, 24) || 'Guest';
  const ins = await db.insert(users).values({
    uid: guestUid,
    username: cleanName,
    email: `${guestUid}@guest.tswv2.local`,
    role: 'TSW User',
  }).returning();
  const u = ins[0];
  await createProfile(u.id, {
    name: cleanName,
    avatar: 'astronaut',
    themeColor: '#5aa2ff',
    isDefault: true,
  });
  return u;
}

export async function getPublicMessages(channel: string) {
  const cleanChannel = ['chat-1', 'chat-2', 'announcements'].includes(channel) ? channel : 'chat-1';

  const res = await db.execute(sql`
    SELECT pm.id, pm.channel, pm.user_id as "userId", pm.content, pm.created_at as "createdAt",
           COALESCE(u.username, 'Guest') as username,
           COALESCE(u.role, 'TSW User') as role,
           COALESCE(p.avatar, 'astronaut') as avatar
    FROM public_messages pm
    LEFT JOIN users u ON u.id = pm.user_id
    LEFT JOIN profiles p ON p.user_id = u.id AND p.is_default = true
    WHERE pm.channel = ${cleanChannel}
    ORDER BY pm.created_at ASC
    LIMIT 200;
  `);

  return (res.rows || []).map((r: any) => ({
    id: r.id,
    channel: r.channel,
    userId: r.userId,
    username: r.username || 'Member',
    role: r.role || 'TSW User',
    roles: parseRoles(r.role),
    avatar: r.avatar || 'astronaut',
    content: r.content,
    createdAt: r.createdAt,
  }));
}

export async function sendPublicMessage(channel: string, userId: number, content: string) {
  const moderation = await getUserModerationState(userId);
  if (moderation.banned) throw new Error('Your account is banned from TSW chat.');
  if (moderation.chatTimeoutUntil && new Date(moderation.chatTimeoutUntil).getTime() > Date.now()) {
    throw new Error('You are timed out from public chat until ' + new Date(moderation.chatTimeoutUntil).toLocaleString());
  }
  const cleanChannel = ['chat-1', 'chat-2', 'announcements'].includes(channel) ? channel : 'chat-1';
  const cleanContent = filterProfanity((content || '').trim());
  if (!cleanContent) {
    throw new Error('Message content cannot be empty');
  }

  // Enforce read-only for announcements channel
  if (cleanChannel === 'announcements') {
    const user = await getUserById(userId);
    const isOwner = user?.role === 'owner' || isUserAdmin(user);
    if (!isOwner) {
      throw new Error('Announcements is a read-only channel. Only the owner can post announcements.');
    }
  }

  const inserted = await db.insert(publicMessages).values({
    channel: cleanChannel,
    userId,
    content: cleanContent,
  }).returning();

  const msg = inserted[0];
  const user = await getUserById(userId);
  const profilesList = await getUserProfiles(userId);
  const activeProfile = profilesList.find(p => p.isDefault) || profilesList[0];

  return {
    id: msg.id,
    channel: msg.channel,
    userId: msg.userId,
    username: user?.username || 'Member',
    role: user?.role || 'TSW User',
    roles: parseRoles(user?.role),
    avatar: activeProfile?.avatar || 'astronaut',
    content: msg.content,
    createdAt: msg.createdAt,
  };
}

export async function deletePublicMessage(userId: number, messageId: number, isAdmin: boolean) {
  if (isAdmin) {
    await db.delete(publicMessages).where(eq(publicMessages.id, messageId));
  } else {
    await db.delete(publicMessages).where(
      and(eq(publicMessages.id, messageId), eq(publicMessages.userId, userId))
    );
  }
  return { success: true };
}

export async function editPublicMessage(userId: number, messageId: number, content: string) {
  const clean = filterProfanity((content || '').trim());
  if (!clean) throw new Error('Message content cannot be empty');
  await db.update(publicMessages).set({ content: clean }).where(
    and(eq(publicMessages.id, messageId), eq(publicMessages.userId, userId))
  );
  return { success: true, content: clean };
}

export function isUserAdmin(user: { id?: number; username?: string | null; email?: string | null; role?: string | null } | null | undefined): boolean {
  if (!user) return false;
  if (user.role === 'owner') return true;
  const email = (user.email || '').toLowerCase().trim();
  const username = (user.username || '').toLowerCase().trim();
  if (email === 'alexc.second@gmail.com') return true;
  if (username === 'alex dalbey') return true;
  return false;
}

export async function getAdminMetrics() {
  await ensureChatTables();
  const userCountRes = await db.execute(sql`
    SELECT count(*)::int as count 
    FROM users 
    WHERE (password_hash IS NOT NULL OR email = 'alexc.second@gmail.com') 
      AND email NOT LIKE '%@scramjet.local' 
      AND email NOT LIKE '%@guest.tswv2.local' 
      AND uid NOT LIKE 'guest_%' 
      AND uid NOT LIKE 'system_%';
  `);

  // Count profiles belonging strictly to real registered users
  const profileCountRes = await db.execute(sql`
    SELECT count(*)::int as count 
    FROM profiles p
    JOIN users u ON p.user_id = u.id
    WHERE (u.password_hash IS NOT NULL OR u.email = 'alexc.second@gmail.com') 
      AND u.email NOT LIKE '%@scramjet.local' 
      AND u.email NOT LIKE '%@guest.tswv2.local' 
      AND u.uid NOT LIKE 'guest_%' 
      AND u.uid NOT LIKE 'system_%';
  `);

  const messageCountRes = await db.execute(sql`SELECT count(*)::int as count FROM messages;`);
  const publicMsgRes = await db.execute(sql`SELECT count(*)::int as count FROM public_messages;`);
  const friendRes = await db.execute(sql`SELECT count(*)::int as count FROM friends;`);
  
  let dbSize = '8.2 MB';
  let activeConnections = 1;
  try {
    const sizeRes = await db.execute(sql`SELECT pg_size_pretty(pg_database_size(current_database())) as dbsize;`);
    if (sizeRes.rows?.[0]) dbSize = String((sizeRes.rows[0] as any).dbsize || '8.2 MB');
  } catch (e) {}

  try {
    const connRes = await db.execute(sql`SELECT count(*)::int as connections FROM pg_stat_activity WHERE datname = current_database();`);
    if (connRes.rows?.[0]) activeConnections = Number((connRes.rows[0] as any).connections || 1);
  } catch (e) {}

  // Real breakdown of public messages by channel
  let channelStats: Record<string, number> = { 'chat-1': 0, 'announcements': 0, 'general': 0 };
  try {
    const chanRes = await db.execute(sql`
      SELECT COALESCE(channel, 'general') as channel, count(*)::int as count 
      FROM public_messages 
      GROUP BY channel;
    `);
    (chanRes.rows || []).forEach((row: any) => {
      channelStats[row.channel] = Number(row.count || 0);
    });
  } catch (e) {}

  // Real distribution of user roles
  let roleStats: Record<string, number> = {};
  try {
    const roleRes = await db.execute(sql`
      SELECT COALESCE(role, 'TSW User') as role, count(*)::int as count 
      FROM users 
      WHERE (password_hash IS NOT NULL OR email = 'alexc.second@gmail.com')
        AND email NOT LIKE '%@scramjet.local'
        AND email NOT LIKE '%@guest.tswv2.local'
        AND uid NOT LIKE 'guest_%'
        AND uid NOT LIKE 'system_%'
      GROUP BY role;
    `);
    (roleRes.rows || []).forEach((row: any) => {
      roleStats[row.role] = Number(row.count || 0);
    });
  } catch (e) {}

  // Real registered users list with individual message counts
  const recentUsersRes = await db.execute(sql`
    SELECT 
      u.id, 
      u.username, 
      u.email, 
      COALESCE(u.role, 'TSW User') as role, 
      u.created_at as "createdAt",
      count(pm.id)::int as "messageCount"
    FROM users u
    LEFT JOIN public_messages pm ON pm.user_id = u.id
    WHERE (u.password_hash IS NOT NULL OR u.email = 'alexc.second@gmail.com' OR u.role != 'TSW User')
      AND u.email NOT LIKE '%@scramjet.local'
      AND u.email NOT LIKE '%@guest.tswv2.local'
      AND u.uid NOT LIKE 'guest_%'
      AND u.uid NOT LIKE 'system_%'
    GROUP BY u.id, u.username, u.email, u.role, u.created_at
    ORDER BY u.id DESC
    LIMIT 100;
  `);

  return {
    users: Number((userCountRes.rows[0] as any)?.count || 0),
    profiles: Number((profileCountRes.rows[0] as any)?.count || 0),
    directMessages: Number((messageCountRes.rows[0] as any)?.count || 0),
    publicMessages: Number((publicMsgRes.rows[0] as any)?.count || 0),
    channelStats,
    roleStats,
    friendships: Number((friendRes.rows[0] as any)?.count || 0),
    dbSize,
    activeConnections,
    recentUsers: (recentUsersRes.rows || []).map((r: any) => ({
      id: r.id,
      username: r.username || 'User',
      email: r.email,
      role: r.role || 'TSW User',
      roles: parseRoles(r.role),
      messageCount: Number(r.messageCount || 0),
      createdAt: r.createdAt
    }))
  };
}

export async function purgeExpiredPublicMessages() {
  return { success: true, count: 0 };
}

export async function updateUserRole(targetUserId: number, rolesInput: string | string[]) {
  await ensureChatTables();
  let rawParts: string[] = [];
  if (Array.isArray(rolesInput)) {
    rawParts = rolesInput;
  } else if (typeof rolesInput === 'string') {
    rawParts = rolesInput.split(',');
  }
  const cleanRoles = parseRoles(rawParts.join(','));
  const roleString = cleanRoles.join(', ');

  const updated = await db.update(users).set({ role: roleString }).where(eq(users.id, targetUserId)).returning({
    id: users.id,
    username: users.username,
    role: users.role,
  });

  if (updated.length === 0) {
    throw new Error('User not found');
  }
  return {
    ...updated[0],
    roles: parseRoles(updated[0].role)
  };
}

export async function getUserProfileCard(userIdOrUsername: number | string) {
  await ensureChatTables();
  let userRows: any[] = [];
  const rawStr = String(userIdOrUsername || '').trim();
  if (typeof userIdOrUsername === 'number' || /^\d+$/.test(rawStr)) {
    const id = typeof userIdOrUsername === 'number' ? userIdOrUsername : parseInt(rawStr, 10);
    userRows = await db.select().from(users).where(eq(users.id, id)).limit(1);
  }
  if (userRows.length === 0 && rawStr) {
    const uname = rawStr.replace(/^@/, '').trim();
    userRows = await db.select().from(users).where(sql`LOWER(${users.username}) = LOWER(${uname})`).limit(1);
  }
  if (userRows.length === 0) {
    throw new Error('User not found');
  }
  const u = userRows[0];
  const profRows = await db.select().from(profiles).where(and(eq(profiles.userId, u.id), eq(profiles.isDefault, true))).limit(1);
  const prof = profRows[0] || (await db.select().from(profiles).where(eq(profiles.userId, u.id)).limit(1))[0];
  let profilePreferences: any = {};
  try { profilePreferences = JSON.parse(prof?.preferences || '{}'); } catch {}
  const isOwner = isUserAdmin(u);
  const roles = parseRoles(u.role);
  if (isOwner && !roles.some(r => r.toLowerCase() === 'owner')) {
    roles.unshift('owner');
  }

  return {
    id: u.id,
    username: u.username || 'Voyager',
    email: u.email,
    role: u.role || 'TSW User',
    roles,
    isOwner,
    avatar: prof?.avatar || (isOwner ? 'crown' : 'astronaut'),
    bio: prof?.bio || (isOwner ? 'TSW Creator & Owner' : 'Explorer of the cosmos'),
    themeColor: prof?.themeColor || '#5aa2ff',
    profilePicture: typeof profilePreferences.profilePicture === 'string' ? profilePreferences.profilePicture : '',
    profileBanner: typeof profilePreferences.profileBanner === 'string' ? profilePreferences.profileBanner : '',
    createdAt: u.createdAt
  };
}

export async function getUserModerationState(userId: number) {
  const rows = await db.select({ preferences: profiles.preferences })
    .from(profiles)
    .where(and(eq(profiles.userId, userId), eq(profiles.isDefault, true)))
    .limit(1);
  let prefs: any = {};
  try { prefs = JSON.parse(rows[0]?.preferences || '{}'); } catch {}
  const moderation = prefs && typeof prefs.moderation === 'object' ? prefs.moderation : {};
  return {
    banned: moderation.banned === true,
    banReason: moderation.banReason || '',
    chatTimeoutUntil: moderation.chatTimeoutUntil || null,
    dmTimeoutUntil: moderation.dmTimeoutUntil || null,
    timeoutReason: moderation.timeoutReason || ''
  };
}

export async function updateUserModerationState(userId: number, patch: Record<string, any>) {
  let rows = await db.select().from(profiles)
    .where(and(eq(profiles.userId, userId), eq(profiles.isDefault, true))).limit(1);
  if (!rows.length) {
    const user = await getUserById(userId);
    if (!user) throw new Error('User not found');
    await createProfile(userId, { name: user.username || 'Voyager', isDefault: true });
    rows = await db.select().from(profiles)
      .where(and(eq(profiles.userId, userId), eq(profiles.isDefault, true))).limit(1);
  }
  const profile = rows[0];
  let prefs: any = {};
  try { prefs = JSON.parse(profile.preferences || '{}'); } catch {}
  const previous = prefs.moderation && typeof prefs.moderation === 'object' ? prefs.moderation : {};
  prefs.moderation = { ...previous, ...patch };
  await db.update(profiles).set({ preferences: JSON.stringify(prefs), updatedAt: new Date() })
    .where(eq(profiles.id, profile.id));
  return getUserModerationState(userId);
}

export async function updateUserBio(userId: number, bio: string) {
  await ensureChatTables();
  const cleanBio = filterProfanity(bio.trim()).slice(0, 300);
  const profs = await db.select().from(profiles).where(eq(profiles.userId, userId));
  if (profs.length > 0) {
    await db.update(profiles).set({ bio: cleanBio, updatedAt: new Date() }).where(eq(profiles.userId, userId));
  } else {
    await db.insert(profiles).values({
      userId,
      name: 'Voyager',
      bio: cleanBio,
      isDefault: true
    });
  }
  return { success: true, bio: cleanBio };
}

export async function getAllMentionsList() {
  await ensureChatTables();
  const res = await db.execute(sql`
    SELECT u.id, u.username, COALESCE(u.role, 'TSW User') as role,
           COALESCE(p.avatar, 'astronaut') as avatar,
           COALESCE(p.theme_color, '#5aa2ff') as "themeColor"
    FROM users u
    LEFT JOIN profiles p ON p.user_id = u.id AND p.is_default = true
    WHERE (u.password_hash IS NOT NULL OR u.email = 'alexc.second@gmail.com')
      AND u.email NOT LIKE '%@scramjet.local'
      AND u.email NOT LIKE '%@guest.tswv2.local'
      AND u.uid NOT LIKE 'guest_%'
      AND u.username IS NOT NULL AND u.username != ''
    ORDER BY u.username ASC
    LIMIT 250;
  `);

  return (res.rows || []).map((r: any) => ({
    id: r.id,
    username: r.username,
    role: r.role,
    roles: parseRoles(r.role),
    avatar: r.avatar || 'astronaut',
    themeColor: r.themeColor || '#5aa2ff'
  }));
}

export async function getAllUsersForOwner() {
  await ensureChatTables();
  const res = await db.execute(sql`
    SELECT u.id, u.username, u.email, COALESCE(u.role, 'TSW User') as role,
           COALESCE(p.avatar, 'astronaut') as avatar
    FROM users u
    LEFT JOIN profiles p ON p.user_id = u.id AND p.is_default = true
    WHERE (u.password_hash IS NOT NULL OR u.email = 'alexc.second@gmail.com')
      AND u.email NOT LIKE '%@scramjet.local'
      AND u.email NOT LIKE '%@guest.tswv2.local'
      AND u.uid NOT LIKE 'guest_%'
      AND u.uid NOT LIKE 'system_%'
      AND u.username IS NOT NULL AND u.username != ''
    ORDER BY u.id ASC;
  `);

  return (res.rows || []).map((r: any) => ({
    id: r.id,
    username: r.username,
    email: r.email,
    role: r.role || 'TSW User',
    roles: parseRoles(r.role),
    avatar: r.avatar || 'astronaut',
  }));
}

export async function sendOfficialBotMessage(channel: string, content: string) {
  await ensureChatTables();
  const cleanChannel = ['chat-1', 'chat-2', 'announcements'].includes(channel) ? channel : 'chat-1';
  let sysUser = await db.select().from(users).where(eq(users.username, 'TSW Official')).limit(1);
  let sysId: number;
  if (sysUser.length > 0) {
    sysId = sysUser[0].id;
  } else {
    const ins = await db.insert(users).values({
      uid: 'system_tsw_official_bot',
      username: 'TSW Official',
      email: 'official@tswv2.com',
      role: 'owner',
    }).returning({ id: users.id });
    sysId = ins[0].id;
    await createProfile(sysId, {
      name: 'TSW Official',
      avatar: 'lightning',
      themeColor: '#5aa2ff',
      isDefault: true,
    });
  }

  const inserted = await db.insert(publicMessages).values({
    channel: cleanChannel,
    userId: sysId,
    content,
  }).returning();

  const msg = inserted[0];
  return {
    id: msg.id,
    channel: msg.channel,
    userId: sysId,
    username: 'TSW Official',
    role: 'owner',
    avatar: 'lightning',
    content: msg.content,
    createdAt: msg.createdAt,
  };
}



// Chat enhancements are temporarily disabled until their Drizzle schema
// migration is applied to the production database. Keep these safe fallbacks
// so optional chat UI polling cannot prevent message history from loading.
export async function toggleMessageReaction() {
  throw new Error('Message reactions are temporarily unavailable.');
}
export async function updateChatPresence() {
  return { success: true };
}
export async function updateChatTyping() {
  return { success: true };
}
export async function getChatTyping() {
  return [];
}
