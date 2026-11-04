import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";

import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import {
	getOrCreateUser,
	getUserProfiles,
	createProfile,
	updateProfile,
	deleteProfile,
	signUpUser,
	loginUser,
	verifySessionToken,
	getUserById,
	getUserModerationState,
	updateUserModerationState,
	searchUsers,
	addFriend,
	removeFriend,
	getFriendsList,
	getIncomingFriendRequests,
	acceptFriendRequest,
	declineFriendRequest,
	getDirectMessages,
	sendDirectMessage,
	deleteDirectMessage,
	editDirectMessage,
	getPublicMessages,
	sendPublicMessage,
	deletePublicMessage,
	editPublicMessage,
	isUserAdmin,
	getAdminMetrics,
	purgeExpiredPublicMessages,
	getOrCreateGuestUser,
	updateUserRole,
	getAllUsersForOwner,
	sendOfficialBotMessage,
	getUserProfileCard,
	updateUserBio,
	getAllMentionsList,
	getUnreadNotifications,
	toggleMessageReaction,
	updateChatPresence,
	updateChatTyping,
	getChatTyping,
	ensureChatTables,
	getMutualFriends,
	logChatModeration,
	getChatModerationLogs,
	getChatReports,
	setChatReportStatus,
	parseRoles,
	userHasRole,
	getActiveUsersForOwner,
	sendUserAlert,
	getPendingUserAlerts,
	dismissUserAlert
} from "./db/users.ts";
import { verifyAuth } from "./middleware/auth.ts";
import { GoogleGenAI } from "@google/genai";
import { db } from "./db/index.ts";
import { sql } from "drizzle-orm";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));
const SERVER_BOOT_TIME = Date.now();
const APP_VERSION = "1.6.10";

// Wisp Configuration: Refer to the documentation at https://www.npmjs.com/package/@mercuryworkshop/wisp-js

logging.set_level(logging.NONE);
Object.assign(wisp.options, {
	allow_udp_streams: false,
	hostname_blacklist: [/example\.com/],
	dns_servers: ["1.1.1.3", "1.0.0.3"],
});

const fastify = Fastify({
	serverFactory: (handler) => {
		return createServer()
			.on("request", (req, res) => {
				res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
				res.setHeader("Cross-Origin-Embedder-Policy", "credentialless");
				res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
				handler(req, res);
			})
			.on("upgrade", (req, socket, head) => {
				if (req.url.endsWith("/wisp/")) wisp.routeRequest(req, socket, head);
				else socket.end();
			});
	},
});

fastify.register(fastifyStatic, {
	root: publicPath,
	decorateReply: true,
});

fastify.register(fastifyStatic, {
	root: scramjetPath,
	prefix: "/scram/",
	decorateReply: false,
});

fastify.register(fastifyStatic, {
	root: libcurlPath,
	prefix: "/libcurl/",
	decorateReply: false,
});

fastify.register(fastifyStatic, {
	root: baremuxPath,
	prefix: "/baremux/",
	decorateReply: false,
});

let ipCache = { value: null, at: 0 };
async function serverIp() {
	if (ipCache.value && Date.now() - ipCache.at < 10 * 60 * 1000) return ipCache.value;
	try {
		const r = await fetch("https://api.ipify.org?format=json", {
			signal: AbortSignal.timeout(4000),
		});
		const j = await r.json();
		if (j && typeof j.ip === "string") {
			ipCache = { value: j.ip, at: Date.now() };
			return j.ip;
		}
	} catch (e) {}
	return ipCache.value;
}

fastify.get("/api/info", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	return {
		time: Date.now(),
		uptime: Math.round(process.uptime()),
		ip: await serverIp(),
	};
});

fastify.get("/api/geo", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	const forwarded = req.headers["x-forwarded-for"];
	const rawIp = forwarded ? forwarded.split(",")[0].trim() : req.ip;
	// Clean IPv6-mapped IPv4 e.g. ::ffff:1.2.3.4
	const clientIp = rawIp ? rawIp.replace(/^::ffff:/, "") : "";

	// Try ipwho.is with client IP if public, otherwise default query
	const queryUrl = (clientIp && !clientIp.startsWith("127.") && !clientIp.startsWith("10.") && !clientIp.startsWith("192.168."))
		? `https://ipwho.is/${clientIp}`
		: "https://ipwho.is/";

	try {
		const res = await fetch(queryUrl, { signal: AbortSignal.timeout(3500) });
		const data = await res.json();
		if (data && data.success !== false && typeof data.latitude === "number" && typeof data.longitude === "number") {
			return {
				success: true,
				ip: data.ip || clientIp,
				city: data.city || "",
				region: data.region || "",
				country: data.country || "",
				latitude: data.latitude,
				longitude: data.longitude,
				timezone: data.timezone?.id || Intl.DateTimeFormat().resolvedOptions().timeZone || "America/New_York",
			};
		}
	} catch (e) {}

	// Fallback to ipapi.co
	try {
		const res2 = await fetch("https://ipapi.co/json/", { signal: AbortSignal.timeout(3500) });
		const data2 = await res2.json();
		if (data2 && typeof data2.latitude === "number" && typeof data2.longitude === "number") {
			return {
				success: true,
				ip: data2.ip || clientIp,
				city: data2.city || "",
				region: data2.region || "",
				country: data2.country_name || "",
				latitude: data2.latitude,
				longitude: data2.longitude,
				timezone: data2.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || "America/New_York",
			};
		}
	} catch (e2) {}

	return {
		success: false,
		latitude: 40.7128,
		longitude: -74.0060,
		timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "America/New_York",
		city: "",
	};
});

async function resolveUserId(req) {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
		const session = verifySessionToken(token);
		if (session && session.userId) return session.userId;

		const verified = await verifyAuth(authHeader);
		if (verified && verified.dbUserId) return verified.dbUserId;
	}
	const clientId = (req.headers["x-client-id"] || "default-voyager").toString().slice(0, 64);
	const u = await getOrCreateUser(clientId, `${clientId}@scramjet.local`);
	return u.id;
}

// Authentication API (Sign Up, Login, Me)
fastify.post("/api/auth/signup", async (req, reply) => {
	try {
		const body = req.body || {};
		const username = (body.username || "").trim();
		const password = body.password || "";
		const email = (body.email || "").trim();

		if (!username || !password) {
			reply.code(400);
			return { success: false, error: "Username and password are required" };
		}

		const result = await signUpUser(username, password, email);
		const isOwner = isUserAdmin(result.user);
		return {
			success: true,
			...result,
			user: {
				...result.user,
				role: result.user.role || (isOwner ? 'owner' : 'TSW User'),
				isOwner,
				isAdmin: isOwner
			}
		};
	} catch (err) {
		req.log.error(err);
		reply.code(400);
		return { success: false, error: err.message || "Failed to create account" };
	}
});

fastify.post("/api/auth/login", async (req, reply) => {
	try {
		const body = req.body || {};
		const username = (body.username || "").trim();
		const password = body.password || "";

		if (!username || !password) {
			reply.code(400);
			return { success: false, error: "Username and password are required" };
		}

		const result = await loginUser(username, password);
		const isOwner = isUserAdmin(result.user);
		return {
			success: true,
			...result,
			user: {
				...result.user,
				role: result.user.role || (isOwner ? 'owner' : 'TSW User'),
				isOwner,
				isAdmin: isOwner
			}
		};
	} catch (err) {
		req.log.error(err);
		reply.code(401);
		return { success: false, error: err.message || "Invalid credentials" };
	}
});

fastify.get("/api/auth/me", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const authHeader = req.headers.authorization;
		if (authHeader) {
			const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
			const session = verifySessionToken(token);
			if (session) {
				const user = await getUserById(session.userId);
				if (user) {
					const profiles = await getUserProfiles(user.id);
					const isOwner = isUserAdmin(user);
					return {
						success: true,
						authenticated: true,
						user: {
							id: user.id,
							username: user.username,
							email: user.email,
							role: user.role || (isOwner ? 'owner' : 'TSW User'),
							roles: parseRoles(user.role || (isOwner ? 'owner' : 'TSW User')),
							isOwner,
							isAdmin: isOwner
						},
						profiles,
						activeProfile: profiles.find(p => p.isDefault) || profiles[0]
					};
				}
			}
		}
		return { success: true, authenticated: false };
	} catch (err) {
		req.log.error(err);
		return { success: false, authenticated: false };
	}
});

// Cloud SQL Profiles API
fastify.get("/api/profiles", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await resolveUserId(req);
		let list = await getUserProfiles(userId);
		if (list.length === 0) {
			const initial = await createProfile(userId, {
				name: "Voyager",
				avatar: "astronaut",
				themeColor: "#5aa2ff",
				bio: "Curator of the cosmos",
				shortcuts: JSON.stringify([
					{ name: "TikTok", url: "https://www.tiktok.com" },
					{ name: "Instagram", url: "https://www.instagram.com" },
					{ name: "GeForce NOW", url: "https://play.geforcenow.com" },
					{ name: "Cork7", url: "https://cork7.com" }
				]),
				preferences: JSON.stringify({
					searchEngine: "https://www.google.com/search?q=",
					stars: true,
					shoot: true,
					bg: "stars"
				}),
				isDefault: true
			});
			list = [initial];
		}
		return { success: true, profiles: list };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Database operation failed" };
	}
});

fastify.post("/api/profiles", async (req, reply) => {
	try {
		const userId = await resolveUserId(req);
		const body = req.body || {};
		if (!body.name || !body.name.trim()) {
			reply.code(400);
			return { success: false, error: "Profile name is required" };
		}
		const profile = await createProfile(userId, {
			name: body.name.trim(),
			avatar: body.avatar || "astronaut",
			themeColor: body.themeColor || "#5aa2ff",
			bio: body.bio || "",
			shortcuts: body.shortcuts,
			preferences: body.preferences,
			isDefault: !!body.isDefault
		});
		return { success: true, profile };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to create profile" };
	}
});

fastify.put("/api/profiles/:id", async (req, reply) => {
	try {
		const userId = await resolveUserId(req);
		const profileId = parseInt(req.params.id, 10);
		if (isNaN(profileId)) {
			reply.code(400);
			return { success: false, error: "Invalid profile ID" };
		}
		const body = req.body || {};
		const updated = await updateProfile(profileId, userId, body);
		if (!updated) {
			reply.code(404);
			return { success: false, error: "Profile not found" };
		}
		return { success: true, profile: updated };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to update profile" };
	}
});

fastify.delete("/api/profiles/:id", async (req, reply) => {
	try {
		const userId = await resolveUserId(req);
		const profileId = parseInt(req.params.id, 10);
		if (isNaN(profileId)) {
			reply.code(400);
			return { success: false, error: "Invalid profile ID" };
		}
		const deleted = await deleteProfile(profileId, userId);
		if (!deleted) {
			reply.code(404);
			return { success: false, error: "Profile not found" };
		}
		return { success: true, deletedId: profileId };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to delete profile" };
	}
});

// Helper for authenticated user in chat and friends
async function getAuthUserId(req, reply) {
	const authHeader = req.headers.authorization;
	if (!authHeader) {
		reply.code(401);
		throw new Error("Authentication required. Please sign in.");
	}
	const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
	const session = verifySessionToken(token);
	if (!session || !session.userId) {
		reply.code(401);
		throw new Error("Session expired or invalid. Please sign in again.");
	}
	const moderation = await getUserModerationState(session.userId);
	if (moderation.banned) {
		reply.code(403);
		throw new Error("This account has been banned from TSW.");
	}
	return session.userId;
}

// TSW AI API. Powered by Google Gemini via @google/genai SDK.
const aiDailyUsage = new Map();
const aiClient = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});

fastify.post("/api/ai/chat", async (req, reply) => {
  reply.header("Cache-Control", "no-store");
  try {
    let userId = null;
    let username = null;
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
      const session = verifySessionToken(token);
      if (session && session.userId) {
        userId = session.userId;
        username = session.username;
      }
    }

    const body = req.body || {};
    const prompt = typeof body.prompt === "string" ? body.prompt.trim() : "";
    if (!prompt) {
      reply.code(400);
      return { success: false, error: "Enter a message first." };
    }
    if (prompt.length > 5000) {
      reply.code(413);
      return { success: false, error: "That message is too long. Keep it under 5,000 characters." };
    }

    const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    if (!apiKey) {
      reply.code(503);
      return { success: false, error: "Gemini isn't configured on the server yet. Ensure GEMINI_API_KEY is available in the environment settings." };
    }

    // Rate limiting: by userId if signed in, or by clientId/ip if guest
    const clientIdentifier = userId ? `user_${userId}` : (req.headers["x-client-id"] || req.ip || "guest");
    const day = new Date().toISOString().slice(0, 10);
    const usageKey = `${day}:${clientIdentifier}`;
    const usage = aiDailyUsage.get(usageKey) || { requests: 0, chars: 0 };
    const maxRequests = userId ? 40 : 25;
    if (usage.requests >= maxRequests || usage.chars + prompt.length > 30000) {
      reply.code(429);
      return { success: false, error: "You've reached the current daily TSW AI limit. Please try again tomorrow or sign in for higher limits." };
    }

    const systemInstruction = "You are TSW AI, a modern, reliable, and helpful assistant built into TSW v2. Answer clearly, concisely, and accurately. Help with schoolwork, coding, gaming questions, writing, or everyday questions. Give working code examples when asked and explain concepts patiently. Do not claim to be ChatGPT or other providers.";

    let replyText = "";
    let usedModel = "gemini-3.1-flash-lite";

    try {
      const response = await aiClient.models.generateContent({
        model: "gemini-3.1-flash-lite",
        contents: prompt,
        config: {
          systemInstruction,
          temperature: 0.7,
        }
      });
      replyText = response.text || "";
    } catch (primaryErr) {
      req.log.warn({ err: primaryErr.message }, "Primary model gemini-3.1-flash-lite failed, trying gemini-3.8-flash fallback");
      try {
        const fallbackRes = await aiClient.models.generateContent({
          model: "gemini-3.8-flash",
          contents: prompt,
          config: {
            systemInstruction,
            temperature: 0.7,
          }
        });
        replyText = fallbackRes.text || "";
        usedModel = "gemini-3.8-flash";
      } catch (fallbackErr) {
        req.log.error({ primary: primaryErr.message, fallback: fallbackErr.message }, "All Gemini models failed");
        throw new Error(primaryErr.message || fallbackErr.message || "Gemini service temporarily unavailable");
      }
    }

    if (!replyText || !replyText.trim()) {
      reply.code(502);
      return { success: false, error: "Gemini returned an empty answer. Please try rephrasing your message." };
    }

    usage.requests += 1;
    usage.chars += prompt.length;
    aiDailyUsage.set(usageKey, usage);

    return {
      success: true,
      reply: replyText.trim(),
      model: usedModel,
      remainingRequests: Math.max(0, maxRequests - usage.requests)
    };
  } catch (err) {
    req.log.error(err, "TSW AI chat error");
    if (!reply.statusCode || reply.statusCode < 400) reply.code(500);
    return { success: false, error: err.message || "AI is temporarily unavailable. Please try again later." };
  }
});

// Friends & Chat API Routes
fastify.get("/api/users/search", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const q = (req.query?.q || "").toString();
		const results = await searchUsers(q, userId);
		return { success: true, users: results };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

// Autocomplete list of all registered users for @ mentions
fastify.get("/api/users/mentions", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const users = await getAllMentionsList();
		return { success: true, users };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to load mention users" };
	}
});

// Real-Time Server Version and Boot Identifier (for update notification popup)
fastify.get("/api/system/version", async (req, reply) => {
	reply.header("Cache-Control", "no-store, no-cache, must-revalidate");
	return {
		success: true,
		version: APP_VERSION,
		bootTime: SERVER_BOOT_TIME,
		timestamp: Date.now()
	};
});

// View a member's profile by ID or by query param (?id= or ?uname=)
fastify.get("/api/users/profile", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const q = req.query || {};
		const lookup = q.id || q.uname || q.username;
		if (!lookup) {
			reply.code(400);
			return { success: false, error: "Missing user identifier" };
		}
		const profile = await getUserProfileCard(lookup);
		return { success: true, profile, user: profile };
	} catch (err) {
		reply.code(404);
		return { success: false, error: err.message || "User not found" };
	}
});

// View a member's full profile by route param (Avatar, Username, Created Date, All Roles, Bio)
fastify.get("/api/users/:id/profile", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const target = req.params.id;
		const profile = await getUserProfileCard(target);
		return { success: true, profile, user: profile };
	} catch (err) {
		reply.code(404);
		return { success: false, error: err.message || "User not found" };
	}
});

// Update current user's profile bio in Cloud SQL
fastify.put("/api/users/me/bio", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const body = req.body || {};
		const bio = (body.bio || "").toString();
		const res = await updateUserBio(userId, bio);
		return { success: true, bio: res.bio };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message || "Failed to update bio" };
	}
});

// Check unread DM notifications for active user
fastify.get("/api/chat/notifications", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const authHeader = req.headers.authorization;
		if (!authHeader) {
			return { success: true, totalUnread: 0, bySender: {} };
		}
		const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
		const session = verifySessionToken(token);
		if (!session || !session.userId) {
			return { success: true, totalUnread: 0, bySender: {} };
		}
		const notifs = await getUnreadNotifications(session.userId);
		return { success: true, ...notifs };
	} catch (err) {
		return { success: false, totalUnread: 0, bySender: {} };
	}
});

// Friend Requests: Incoming pending requests
fastify.get("/api/friends/requests", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const requests = await getIncomingFriendRequests(userId);
		return { success: true, requests };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

// Friend Requests: Accept request
fastify.post("/api/friends/accept/:requesterId", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const requesterId = parseInt(req.params.requesterId, 10);
		if (isNaN(requesterId)) {
			reply.code(400);
			return { success: false, error: "Invalid requester ID" };
		}
		const result = await acceptFriendRequest(userId, requesterId);
		return { success: true, friend: result.friend };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

// Friend Requests: Decline request
fastify.post("/api/friends/decline/:requesterId", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const requesterId = parseInt(req.params.requesterId, 10);
		if (isNaN(requesterId)) {
			reply.code(400);
			return { success: false, error: "Invalid requester ID" };
		}
		await declineFriendRequest(userId, requesterId);
		return { success: true };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.get("/api/friends", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const list = await getFriendsList(userId);
		return { success: true, friends: list };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

fastify.post("/api/friends", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const body = req.body || {};
		const username = (body.username || "").trim();
		if (!username) {
			reply.code(400);
			return { success: false, error: "Please enter a username to add" };
		}
		const friend = await addFriend(userId, username);
		return { success: true, friend };
	} catch (err) {
		reply.code(err.message.includes("not found") ? 404 : 400);
		return { success: false, error: err.message };
	}
});

fastify.delete("/api/friends/:friendId", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const friendId = parseInt(req.params.friendId, 10);
		if (isNaN(friendId)) {
			reply.code(400);
			return { success: false, error: "Invalid friend ID" };
		}
		await removeFriend(userId, friendId);
		return { success: true };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.get("/api/messages/:friendId", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const friendId = parseInt(req.params.friendId, 10);
		if (isNaN(friendId)) {
			reply.code(400);
			return { success: false, error: "Invalid friend ID" };
		}
		const messages = await getDirectMessages(userId, friendId);
		return { success: true, messages };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.post("/api/messages/:friendId", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const friendId = parseInt(req.params.friendId, 10);
		const body = req.body || {};
		const content = (body.content || "").trim();
		if (isNaN(friendId)) {
			reply.code(400);
			return { success: false, error: "Invalid friend ID" };
		}
		if (!content) {
			reply.code(400);
			return { success: false, error: "Message cannot be empty" };
		}
		const message = await sendDirectMessage(userId, friendId, content);
		return { success: true, message };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

// Public Channels API Routes (chat-1, chat-2, announcements)
fastify.get("/api/public-messages/:channel", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const channel = (req.params.channel || "chat-1").toString();
		const messages = await getPublicMessages(channel);
		return { success: true, channel, messages };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.post("/api/public-messages/:channel", async (req, reply) => {
	try {
		let userId = null;
		const authHeader = req.headers.authorization;
		if (authHeader) {
			const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
			const session = verifySessionToken(token);
			if (session && session.userId) {
				const existingUser = await getUserById(session.userId);
				if (existingUser) {
					userId = existingUser.id;
				}
			}
		}

		// Allow guest posting in community channels (chat-1, chat-2)
		if (!userId) {
			const channelName = (req.params.channel || "chat-1").toString();
			if (channelName === "announcements") {
				reply.code(401);
				return { success: false, error: "Only the Owner (Alex Dalbey) can post in #announcements." };
			}
			const clientId = (req.headers["x-client-id"] || req.body?.clientId || "").toString().trim() || ("guest_" + Math.random().toString(36).substring(2, 9));
			const guestName = (req.body?.guestName || req.body?.username || "Guest").toString().slice(0, 30).trim() || "Guest";
			const guestUser = await getOrCreateGuestUser(clientId, guestName);
			userId = guestUser.id;
		}

		const channel = (req.params.channel || "chat-1").toString();
		const body = req.body || {};
		const content = (body.content || "").trim();
		if (!content) {
			reply.code(400);
			return { success: false, error: "Message cannot be empty" };
		}
		const message = await sendPublicMessage(channel, userId, content);
		return { success: true, message };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

// Chat reactions, typing and online presence
fastify.post("/api/chat/reactions/:type/:id", async (req, reply) => {
  try {
    const userId = await getAuthUserId(req, reply);
    const type = req.params.type === "dm" ? "dm" : req.params.type === "public" ? "public" : null;
    const messageId = parseInt(req.params.id, 10);
    const emoji = (req.body?.emoji || "").toString();
    if (!type || !Number.isInteger(messageId) || messageId < 1) {
      reply.code(400);
      return { success: false, error: "Invalid message" };
    }
    const reactions = await toggleMessageReaction(userId, type, messageId, emoji);
    return { success: true, reactions };
  } catch (err) {
    reply.code(400);
    return { success: false, error: err.message || "Could not update reaction" };
  }
});

fastify.post("/api/chat/presence", async (req, reply) => {
  try {
    const userId = await getAuthUserId(req, reply);
    await updateChatPresence(userId);
    return { success: true };
  } catch (err) {
    reply.code(401);
    return { success: false, error: "Sign in to update presence" };
  }
});

fastify.post("/api/chat/typing", async (req, reply) => {
  try {
    const userId = await getAuthUserId(req, reply);
    const body = req.body || {};
    const type = body.type === "dm" ? "dm" : body.type === "public" ? "public" : null;
    const contextId = (body.contextId || "").toString().slice(0, 80);
    if (!type || !contextId) {
      reply.code(400);
      return { success: false, error: "Invalid typing context" };
    }
    await updateChatTyping(userId, type, contextId, !!body.isTyping);
    return { success: true };
  } catch (err) {
    reply.code(401);
    return { success: false, error: "Sign in to update typing status" };
  }
});

fastify.get("/api/chat/typing/:type/:contextId", async (req, reply) => {
  reply.header("Cache-Control", "no-store");
  try {
    const userId = await getAuthUserId(req, reply);
    const type = req.params.type === "dm" ? "dm" : req.params.type === "public" ? "public" : null;
    if (!type) {
      reply.code(400);
      return { success: false, error: "Invalid typing context" };
    }
    const users = await getChatTyping(userId, type, req.params.contextId);
    return { success: true, users };
  } catch (err) {
    reply.code(401);
    return { success: false, error: "Sign in to check typing status" };
  }
});

// Community Reports Endpoint
fastify.post("/api/reports", async (req, reply) => {
  reply.header("Cache-Control", "no-store");
  try {
    const reporterId = await getAuthUserId(req, reply);
    await ensureChatTables();
    const body = req.body || {};
    const messageId = Number.parseInt(body.messageId, 10);
    const type = body.type === "dm" ? "dm" : "public";
    const reason = String(body.reason || "").trim().slice(0, 300);
    if (!Number.isInteger(messageId) || messageId < 1 || !reason) {
      reply.code(400);
      return { success: false, error: "Choose a message and provide a reason." };
    }
    let targetUserId = null;
    if (type === "public") {
      const found = await db.execute(sql`SELECT user_id FROM public_messages WHERE id = ${messageId} LIMIT 1`);
      targetUserId = found.rows?.[0]?.user_id || null;
    } else {
      const found = await db.execute(sql`SELECT sender_id FROM messages WHERE id = ${messageId} AND (sender_id = ${reporterId} OR receiver_id = ${reporterId}) LIMIT 1`);
      targetUserId = found.rows?.[0]?.sender_id || null;
    }
    if (!targetUserId) {
      reply.code(404);
      return { success: false, error: "Message not found." };
    }
    await db.execute(sql`INSERT INTO chat_reports (reporter_id,reported_user_id,message_type,message_id,reason) VALUES (${reporterId},${targetUserId},${type},${messageId},${reason})`);
    return { success: true };
  } catch (err) {
    reply.code(400);
    return { success: false, error: err.message || "Could not submit report." };
  }
});

fastify.get("/api/owner/chat-reports", async (req, reply) => {
  try {
    const userId = await getAuthUserId(req, reply);
    const user = await getUserById(userId);
    if (!isUserAdmin(user)) { reply.code(403); return { success: false, error: "Owner access required." }; }
    await ensureChatTables();
    const result = await db.execute(sql`SELECT r.id,r.message_type AS "messageType",r.message_id AS "messageId",r.reason,r.details,r.status,r.created_at AS "createdAt",u.username AS "reporter",t.username AS "reportedUser" FROM chat_reports r JOIN users u ON u.id=r.reporter_id LEFT JOIN users t ON t.id=r.reported_user_id ORDER BY r.created_at DESC LIMIT 200`);
    return { success: true, reports: result.rows || [] };
  } catch (err) { reply.code(400); return { success: false, error: err.message }; }
});

// Owner Commands & System Controls (Only account with Owner role can execute)
fastify.post("/api/chat/command", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const user = await getUserById(userId);
		const isOwner = user && (
			user.role === 'owner' ||
			(user.username && user.username.toLowerCase() === 'alex dalbey') ||
			(user.email && user.email.toLowerCase() === 'alexc.second@gmail.com')
		);

		if (!isOwner) {
			reply.code(403);
			return { success: false, error: "Access Denied: Only the account with the Owner role (Alex Dalbey) can execute system commands." };
		}

		const body = req.body || {};
		const rawCmd = (body.command || "").trim();
		const channel = (body.channel || "chat-1").toString();
		const lower = rawCmd.toLowerCase();

		if (lower === "/discord") {
			// TSW Official posts: "join our discord now!"
			const botMsg = await sendOfficialBotMessage(channel, "join our discord now! https://discord.gg/tsw");
			return {
				success: true,
				command: "/discord",
				action: "bot_message",
				message: "TSW Official posted Discord invite.",
				botMessage: botMsg
			};
		}

		if (lower === "/commands" || lower === "/comands") {
			const commandsList = [
				{ cmd: "/discord", desc: "TSW Official automatically posts 'join our discord now!' into the current channel." },
				{ cmd: "/commands (or /comands)", desc: "Lists all working commands and owner controls." },
				{ cmd: "/give role", desc: "Opens role assigner with user & role dropdowns to instantly grant roles." }
			];
			return {
				success: true,
				command: "/commands",
				action: "show_commands",
				commands: commandsList
			};
		}

		if (lower.startsWith("/give role") || lower.startsWith("/giverole")) {
			// If targetUserId & role are passed directly
			const roleParam = body.roles || body.role || body.newRole;
			if (body.targetUserId && roleParam) {
				const targetId = parseInt(body.targetUserId, 10);
				const updated = await updateUserRole(targetId, roleParam);
				const botMsg = await sendOfficialBotMessage(channel, `👑 @${updated.username} was granted roles [${updated.roles.join(', ')}] by Owner Alex Dalbey.`);
				return {
					success: true,
					command: "/give role",
					action: "role_granted",
					targetUser: updated,
					botMessage: botMsg
				};
			}
			// Otherwise request frontend to show the role dropdown picker
			return {
				success: true,
				command: "/give role",
				action: "open_role_modal"
			};
		}

		reply.code(400);
		return {
			success: false,
			error: `Unknown command "${rawCmd}". Type /commands or /comands to list all working commands.`
		};
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

// Owner endpoint to get all users for the role assignment dropdown
fastify.get("/api/owner/users", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const user = await getUserById(userId);
		const isOwner = user && (
			user.role === 'owner' ||
			(user.username && user.username.toLowerCase() === 'alex dalbey') ||
			(user.email && user.email.toLowerCase() === 'alexc.second@gmail.com')
		);

		if (!isOwner) {
			reply.code(403);
			return { success: false, error: "Only the Owner can access user directory for role management." };
		}

		const usersList = await getAllUsersForOwner();
		return { success: true, users: usersList };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

// Owner-only moderation controls. State is stored in the existing profile preferences field.
fastify.post("/api/owner/moderate-user", async (req, reply) => {
  try {
    const ownerId = await getAuthUserId(req, reply);
    const owner = await getUserById(ownerId);
    if (!isUserAdmin(owner)) {
      reply.code(403);
      return { success: false, error: "Only the Owner can moderate users." };
    }
    const body = req.body || {};
    const targetUserId = Number.parseInt(body.targetUserId, 10);
    const action = String(body.action || "");
    if (!Number.isInteger(targetUserId) || targetUserId <= 0 || targetUserId === ownerId) {
      reply.code(400);
      return { success: false, error: "Choose a valid user to moderate." };
    }
    const target = await getUserById(targetUserId);
    if (!target) {
      reply.code(404);
      return { success: false, error: "User not found." };
    }
    let patch = {};
    if (action === "ban") {
      patch = { banned: true, banReason: String(body.reason || "No reason provided").slice(0, 240), bannedAt: new Date().toISOString() };
    } else if (action === "unban") {
      patch = { banned: false, banReason: "", bannedAt: null };
    } else if (action === "timeout") {
      const minutes = Math.max(1, Math.min(10080, Number.parseInt(body.minutes, 10) || 10));
      const until = new Date(Date.now() + minutes * 60000).toISOString();
      const scope = ["chat", "dm", "both"].includes(body.scope) ? body.scope : "both";
      if (scope === "chat" || scope === "both") patch.chatTimeoutUntil = until;
      if (scope === "dm" || scope === "both") patch.dmTimeoutUntil = until;
      patch.timeoutReason = String(body.reason || "No reason provided").slice(0, 240);
    } else if (action === "clear-timeout") {
      patch = { chatTimeoutUntil: null, dmTimeoutUntil: null, timeoutReason: "" };
    } else {
      reply.code(400);
      return { success: false, error: "Unknown moderation action." };
    }
    const moderation = await updateUserModerationState(targetUserId, patch);
    await logChatModeration(ownerId, targetUserId, action, String(body.reason || ''));
    return { success: true, target: { id: target.id, username: target.username }, moderation };
  } catch (err) {
    reply.code(err.message.includes("Authentication") ? 401 : 400);
    return { success: false, error: err.message || "Moderation action failed." };
  }
});

// Owner endpoint to assign role to a specific user
fastify.post("/api/owner/give-role", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const user = await getUserById(userId);
		const isOwner = user && (
			user.role === 'owner' ||
			(user.username && user.username.toLowerCase() === 'alex dalbey') ||
			(user.email && user.email.toLowerCase() === 'alexc.second@gmail.com')
		);

		if (!isOwner) {
			reply.code(403);
			return { success: false, error: "Only the Owner can grant roles." };
		}

		const body = req.body || {};
		const targetUserId = parseInt(body.targetUserId, 10);
		const rolesParam = body.roles || body.role || body.newRole;
		const channel = (body.channel || "chat-1").toString();

		if (isNaN(targetUserId) || !rolesParam) {
			reply.code(400);
			return { success: false, error: "targetUserId and roles are required." };
		}

		const updatedUser = await updateUserRole(targetUserId, rolesParam);
		const rolesListStr = updatedUser.roles.join(', ');
		const botMsg = await sendOfficialBotMessage(channel, `👑 @${updatedUser.username} was granted roles [${rolesListStr}] by Owner Alex Dalbey.`);

		return {
			success: true,
			user: updatedUser,
			botMessage: botMsg,
			message: `Successfully updated @${updatedUser.username} to ${rolesListStr}`
		};
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

// Direct Message edit and delete
fastify.delete("/api/messages/:id", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const messageId = parseInt(req.params.id, 10);
		if (isNaN(messageId)) {
			reply.code(400);
			return { success: false, error: "Invalid message ID" };
		}
		const user = await getUserById(userId);
		const isAdmin = isUserAdmin(user);
		const result = await deleteDirectMessage(userId, messageId, isAdmin);
		return { success: true, ...result };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.put("/api/messages/:id", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const messageId = parseInt(req.params.id, 10);
		const body = req.body || {};
		const content = (body.content || "").trim();
		if (isNaN(messageId) || !content) {
			reply.code(400);
			return { success: false, error: "Invalid message ID or empty content" };
		}
		const result = await editDirectMessage(userId, messageId, content);
		return { success: true, ...result };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

// Public Message edit and delete
fastify.delete("/api/public-messages/:id", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const messageId = parseInt(req.params.id, 10);
		if (isNaN(messageId)) {
			reply.code(400);
			return { success: false, error: "Invalid message ID" };
		}
		const user = await getUserById(userId);
		const isAdmin = isUserAdmin(user);
		const result = await deletePublicMessage(userId, messageId, isAdmin);
		return { success: true, ...result };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.put("/api/public-messages/:id", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const messageId = parseInt(req.params.id, 10);
		const body = req.body || {};
		const content = (body.content || "").trim();
		if (isNaN(messageId) || !content) {
			reply.code(400);
			return { success: false, error: "Invalid message ID or empty content" };
		}
		const result = await editPublicMessage(userId, messageId, content);
		return { success: true, ...result };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

// Cloud Admin & Metrics Endpoints
fastify.get("/api/admin/metrics", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const authHeader = req.headers.authorization;
		let currentUser = null;
		if (authHeader) {
			const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
			const session = verifySessionToken(token);
			if (session && session.userId) {
				currentUser = await getUserById(session.userId);
			}
		}

		const isOwner = isUserAdmin(currentUser);
		if (!isOwner) {
			reply.code(403);
			return { success: false, error: "Access denied. Only the Owner (Alex Dalbey) can access Cloud Admin." };
		}
		const dbMetrics = await getAdminMetrics();

		const uptimeSec = Math.floor(process.uptime());
		const hours = Math.floor(uptimeSec / 3600);
		const mins = Math.floor((uptimeSec % 3600) / 60);
		const secs = uptimeSec % 60;
		const uptimeStr = `${hours}h ${mins}m ${secs}s`;

		const mem = process.memoryUsage();
		const memStats = {
			rssMB: (mem.rss / 1024 / 1024).toFixed(1),
			heapUsedMB: (mem.heapUsed / 1024 / 1024).toFixed(1),
			heapTotalMB: (mem.heapTotal / 1024 / 1024).toFixed(1),
			heapPercent: Math.round((mem.heapUsed / mem.heapTotal) * 100)
		};

		return {
			success: true,
			isAdmin: isOwner,
			ownerEmail: "alexc.second@gmail.com",
			activeUser: currentUser ? {
				id: currentUser.id,
				username: currentUser.username,
				email: currentUser.email,
				role: currentUser.role || 'owner',
				isAdmin: isUserAdmin(currentUser)
			} : null,
			system: {
				appletId: process.env.APPLET_ID || "15c18e45-b808-43b5-a99a-29ffca78b6df",
				serviceUrl: "https://ais-dev-irpbeztud5alnivyn63pfn-183866442448.us-east1.run.app",
				databaseHost: "PostgreSQL Cloud SQL Instance",
				databaseName: process.env.SQL_DB_NAME || "cloud_sql_development_database",
				region: "us-east1"
			},
			server: {
				status: "Online",
				uptime: uptimeStr,
				uptimeSeconds: uptimeSec,
				nodeVersion: process.version,
				platform: process.platform + " (" + process.arch + ")",
				memory: memStats,
				port: port
			},
			database: dbMetrics
		};
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to load cloud metrics" };
	}
});

fastify.post("/api/admin/purge-expired", async (req, reply) => {
	try {
		const authHeader = req.headers.authorization;
		if (!authHeader) {
			reply.code(401);
			return { success: false, error: "Authentication required" };
		}
		const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
		const session = verifySessionToken(token);
		if (!session || !session.userId) {
			reply.code(401);
			return { success: false, error: "Invalid session" };
		}
		const user = await getUserById(session.userId);
		if (!isUserAdmin(user)) {
			reply.code(403);
			return { success: false, error: "Forbidden: Super Admin access required" };
		}
		const res = await purgeExpiredPublicMessages();
		return { success: true, purgedCount: res.count };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to purge expired records" };
	}
});

fastify.get("/api/friends/mutual/:id", async (req, reply) => {
  try {
    const uid = await getAuthUserId(req, reply);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id < 1) {
      reply.code(400);
      return { success: false, error: "Invalid user" };
    }
    return { success: true, friends: await getMutualFriends(uid, id) };
  } catch (err) {
    reply.code(400);
    return { success: false, error: err.message };
  }
});

fastify.get("/api/owner/chat-logs", async (req, reply) => {
  try {
    const uid = await getAuthUserId(req, reply);
    if (!isUserAdmin(await getUserById(uid))) {
      reply.code(403);
      return { success: false, error: "Owner access required" };
    }
    return { success: true, logs: await getChatModerationLogs() };
  } catch (err) {
    reply.code(400);
    return { success: false, error: err.message };
  }
});

fastify.patch("/api/owner/chat-reports/:id", async (req, reply) => {
  try {
    const uid = await getAuthUserId(req, reply);
    if (!isUserAdmin(await getUserById(uid))) {
      reply.code(403);
      return { success: false, error: "Owner access required" };
    }
    const id = Number.parseInt(req.params.id, 10);
    const status = ["open", "reviewed", "dismissed"].includes(req.body?.status) ? req.body.status : null;
    if (!id || !status) {
      reply.code(400);
      return { success: false, error: "Invalid report update" };
    }
    await setChatReportStatus(id, status);
    return { success: true };
  } catch (err) {
    reply.code(400);
    return { success: false, error: err.message };
  }
});

// Owner Only: Active users list for Send User Alert
fastify.get("/api/owner/active-users", async (req, reply) => {
  reply.header("Cache-Control", "no-store");
  try {
    const uid = await getAuthUserId(req, reply);
    const user = await getUserById(uid);
    if (!isUserAdmin(user)) {
      reply.code(403);
      return { success: false, error: "Owner access required." };
    }
    const users = await getActiveUsersForOwner();
    return { success: true, users };
  } catch (err) {
    reply.code(err.message.includes("Authentication") ? 401 : 400);
    return { success: false, error: err.message };
  }
});

// Owner Only: Send high-priority user alert popup
fastify.post("/api/owner/send-alert", async (req, reply) => {
  reply.header("Cache-Control", "no-store");
  try {
    const uid = await getAuthUserId(req, reply);
    const user = await getUserById(uid);
    if (!isUserAdmin(user)) {
      reply.code(403);
      return { success: false, error: "Owner access required." };
    }
    const body = req.body || {};
    const targetUserId = parseInt(body.targetUserId, 10);
    const message = String(body.message || "").trim();
    if (!Number.isInteger(targetUserId) || targetUserId < 1) {
      reply.code(400);
      return { success: false, error: "Please select an active member." };
    }
    if (!message) {
      reply.code(400);
      return { success: false, error: "Alert message cannot be empty." };
    }
    const result = await sendUserAlert(uid, targetUserId, message);
    if (!result.success || !result.delivered) {
      reply.code(400);
      return result;
    }
    return result;
  } catch (err) {
    reply.code(err.message.includes("Authentication") ? 401 : 400);
    return { success: false, error: err.message };
  }
});

// Authenticated User: Check for pending alerts
fastify.get("/api/users/me/alerts", async (req, reply) => {
  reply.header("Cache-Control", "no-store");
  try {
    const uid = await getAuthUserId(req, reply);
    const alerts = await getPendingUserAlerts(uid);
    return { success: true, alerts };
  } catch (err) {
    reply.code(err.message.includes("Authentication") ? 401 : 400);
    return { success: false, alerts: [] };
  }
});

// Authenticated User: Dismiss/acknowledge alert
fastify.post("/api/users/me/alerts/:id/dismiss", async (req, reply) => {
  reply.header("Cache-Control", "no-store");
  try {
    const uid = await getAuthUserId(req, reply);
    const alertId = parseInt(req.params.id, 10);
    if (isNaN(alertId)) {
      reply.code(400);
      return { success: false, error: "Invalid alert ID" };
    }
    await dismissUserAlert(uid, alertId);
    return { success: true };
  } catch (err) {
    reply.code(err.message.includes("Authentication") ? 401 : 400);
    return { success: false, error: err.message };
  }
});

fastify.setNotFoundHandler((res, reply) => {
	return reply.code(404).type("text/html").sendFile("404.html");
});

fastify.server.on("listening", () => {
	const address = fastify.server.address();
	console.log(`Scramjet proxy listening on http://0.0.0.0:${address.port}`);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server");
	fastify.close();
	process.exit(0);
}

let port = parseInt(process.env.PORT || "");
const portArgIdx = process.argv.indexOf("--port");
if (portArgIdx !== -1 && process.argv[portArgIdx + 1]) {
  const parsed = parseInt(process.argv[portArgIdx + 1], 10);
  if (!isNaN(parsed)) port = parsed;
}
if (isNaN(port)) port = 3000;

fastify.listen({
	port: port,
	host: "0.0.0.0",
});

