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
	sendOfficialBotMessage
} from "./db/users.ts";
import { verifyAuth } from "./middleware/auth.ts";
import { GoogleGenAI } from "@google/genai";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));

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
				userId = session.userId;
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
			const roleParam = body.role || body.newRole;
			if (body.targetUserId && roleParam) {
				const targetId = parseInt(body.targetUserId, 10);
				const role = roleParam.toString().trim();
				const updated = await updateUserRole(targetId, role);
				const botMsg = await sendOfficialBotMessage(channel, `👑 @${updated.username} was granted the role [${updated.role}] by Owner Alex Dalbey.`);
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
		const role = (body.role || body.newRole || "").toString().trim();
		const channel = (body.channel || "chat-1").toString();

		if (isNaN(targetUserId) || !role) {
			reply.code(400);
			return { success: false, error: "targetUserId and role are required." };
		}

		const updatedUser = await updateUserRole(targetUserId, role);
		const botMsg = await sendOfficialBotMessage(channel, `👑 @${updatedUser.username} was granted the role [${updatedUser.role}] by Owner Alex Dalbey.`);

		return {
			success: true,
			user: updatedUser,
			botMessage: botMsg,
			message: `Successfully updated @${updatedUser.username} to ${updatedUser.role}`
		};
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

// Friend Requests API Routes
fastify.get("/api/friends/requests", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const requests = await getIncomingFriendRequests(userId);
		return { success: true, requests };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.post("/api/friends/accept/:requesterId", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const requesterId = parseInt(req.params.requesterId, 10);
		if (isNaN(requesterId)) {
			reply.code(400);
			return { success: false, error: "Invalid requester ID" };
		}
		const result = await acceptFriendRequest(userId, requesterId);
		return { success: true, ...result };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.post("/api/friends/decline/:requesterId", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const requesterId = parseInt(req.params.requesterId, 10);
		if (isNaN(requesterId)) {
			reply.code(400);
			return { success: false, error: "Invalid requester ID" };
		}
		const result = await declineFriendRequest(userId, requesterId);
		return { success: true, ...result };
	} catch (err) {
		reply.code(400);
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
		const result = await deleteDirectMessage(userId, messageId);
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

		// Calculate daily AI usage metrics
		let totalAiRequests = 0;
		let totalAiChars = 0;
		for (const [, usage] of aiDailyUsage.entries()) {
			totalAiRequests += (usage.requests || 0);
			totalAiChars += (usage.chars || 0);
		}

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
			isAdmin,
			superAdminEmail: "alexc.second@gmail.com",
			activeUser: currentUser ? {
				id: currentUser.id,
				username: currentUser.username,
				email: currentUser.email,
				isAdmin: isUserAdmin(currentUser)
			} : null,
			gcp: {
				projectId: "strong-voyage-v8p5g",
				designatedOwner: "alexc.second@gmail.com",
				requestedRole: "roles/monitoring.editor",
				cloudRunRegion: "us-east1",
				serviceUrl: "https://ais-dev-irpbeztud5alnivyn63pfn-183866442448.us-east1.run.app",
				monitoringUrl: "https://console.cloud.google.com/monitoring?project=strong-voyage-v8p5g",
				iamTroubleshooterUrl: "https://console.cloud.google.com/iam-admin/troubleshooter/summary;permissions=monitoring.uptimeCheckConfigs.create;token=AX6qVRYTS4hGZsWN-r57SK2_xhsMSVbxO3gWCGWeR2IvNqQVt5eiGqRsmfSC99ydAWz4YgALXGuMyNH9vDKYGDWhMbOvdAHgzQje9D4r-PK4KGT1ciOJyOHY6oAo40-iSsnPVimOAqU9AOAPQ53Do8H-15SQ_fdlWvkZmnfNUv3jnD4gQPGejvK6kg"
			},
			server: {
				status: "Healthy / Online",
				uptime: uptimeStr,
				uptimeSeconds: uptimeSec,
				nodeVersion: process.version,
				platform: process.platform + " (" + process.arch + ")",
				memory: memStats,
				port: port
			},
			database: dbMetrics,
			ai: {
				status: (process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY) ? "Online / Connected" : "Not configured",
				primaryModel: "Gemini 2.5 Flash",
				fallbackModel: "Gemini 2.5 Flash-Lite",
				dailyRequests: totalAiRequests,
				dailyChars: totalAiChars,
				dailyLimitPerUser: 20
			}
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
