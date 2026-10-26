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
	editPublicMessage
} from "./db/users.ts";
import { verifyAuth } from "./middleware/auth.ts";

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
		return { success: true, ...result };
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
		return { success: true, ...result };
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
					return {
						success: true,
						authenticated: true,
						user: { id: user.id, username: user.username, email: user.email },
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

// TSW AI API. The provider key is stored only in the server environment (GEMINI_API_KEY).
const aiDailyUsage = new Map();
fastify.post("/api/ai/chat", async (req, reply) => {
  reply.header("Cache-Control", "no-store");
  try {
    const userId = await getAuthUserId(req, reply);
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
    if (body.model && body.model !== "gemini") {
      reply.code(400);
      return { success: false, error: "That AI provider is not connected yet. Gemini is currently the only available model." };
    }
    const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    if (!apiKey) {
      reply.code(503);
      return { success: false, error: "Gemini isn't configured on the TSW server yet. Add GEMINI_API_KEY in the server's environment settings." };
    }
    // A basic in-memory limit helps protect the shared free quota; this resets when the server restarts.
    const day = new Date().toISOString().slice(0, 10);
    const usageKey = day + ":" + String(userId);
    const usage = aiDailyUsage.get(usageKey) || { requests: 0, chars: 0 };
    if (usage.requests >= 20 || usage.chars + prompt.length > 20000) {
      reply.code(429);
      return { success: false, error: "You've reached the current daily TSW AI limit. Please try again tomorrow or use a shorter prompt." };
    }
    const requestGemini = async (model) => fetch("https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: "You are TSW AI, a reliable, helpful assistant for everyday questions, coding, and homework. Read the full request carefully, reason through the problem before answering, check your answer for mistakes, and use tools or calculations only when actually available. Do not reveal private hidden chain-of-thought; instead give a clear answer with useful reasoning, steps, assumptions, and checks when they help. Be friendly, age-appropriate, direct, and honest when unsure. For coding, give working complete examples when appropriate and explain likely causes of errors. Explain schoolwork so the student can learn rather than simply encouraging cheating. Do not claim to be ChatGPT or another provider." }] },
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: 900, temperature: 0.7 }
      }),
      signal: AbortSignal.timeout(30000)
    });
    // Retry transient overloads, then fall back to a lighter model if Flash is busy.
    let response = await requestGemini("gemini-2.5-flash");
    if (response.status === 503 || response.status === 500) {
      await new Promise(resolve => setTimeout(resolve, 900));
      response = await requestGemini("gemini-2.5-flash");
    }
    if (response.status === 503 || response.status === 500 || response.status === 429) {
      req.log.warn({ status: response.status }, "Primary Gemini model unavailable; trying Flash-Lite fallback");
      response = await requestGemini("gemini-2.5-flash-lite");
    }
    if (response.status === 429) {
      reply.code(429);
      return { success: false, error: "Google's Gemini API quota or rate limit is currently reached for the available models. Check your Google AI Studio usage and try again later." };
    }
    if (response.status === 401 || response.status === 403) {
      req.log.error("Gemini API authentication/configuration failed.");
      reply.code(503);
      return { success: false, error: "TSW AI's Google API key was rejected. Check the key and API access in Google AI Studio." };
    }
    if (!response.ok) {
      let providerMessage = "";
      try {
        const errorData = await response.json();
        providerMessage = typeof errorData?.error?.message === "string" ? errorData.error.message : "";
      } catch (_) {}
      req.log.warn({ status: response.status, providerMessage }, "Gemini API request failed after fallback");
      reply.code(502);
      if (response.status === 404) {
        return { success: false, error: "The Gemini model isn't available to this API key. Check model access in Google AI Studio." };
      }
      if (response.status === 400) {
        return { success: false, error: "Gemini rejected the request. Check the server logs for the provider's error details." };
      }
      if (response.status === 503 || response.status === 500) {
        return { success: false, error: "Google's Gemini API is overloaded right now, including its fallback model. Please try again in a minute." };
      }
      return { success: false, error: "Gemini API request failed (HTTP " + response.status + "). " + (providerMessage ? providerMessage.slice(0, 220) : "Check the server logs for details.") };
    }
    const data = await response.json();
    const answer = (data.candidates?.[0]?.content?.parts || []).map(part => part.text || "").join("").trim();
    if (!answer) {
      reply.code(502);
      return { success: false, error: "Gemini returned an empty answer. Try rewording your question." };
    }
    usage.requests += 1;
    usage.chars += prompt.length;
    aiDailyUsage.set(usageKey, usage);
    return { success: true, reply: answer, model: "Gemini 2.5 Flash with Flash-Lite fallback", remainingRequests: Math.max(0, 20 - usage.requests) };
  } catch (err) {
    if (err.message && err.message.includes("Authentication")) reply.code(401);
    else if (!reply.statusCode || reply.statusCode < 400) reply.code(500);
    return { success: false, error: err.message && err.message.includes("Authentication") ? err.message : "AI is temporarily unavailable. Please try again later." };
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
		const userId = await getAuthUserId(req, reply);
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
		const username = (user?.username || "").toLowerCase();
		const isAdmin = username.includes("admin") || username.includes("tsw");
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
