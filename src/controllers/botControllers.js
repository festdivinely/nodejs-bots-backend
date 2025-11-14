// src/controllers/botController.js
import asyncHandler from "express-async-handler";
import axios from "axios";
import { ObjectId } from "mongodb";

// @desc    Create a new bot template
// @route   POST /api/bot
// @access  Private/Admin
export const createBotTemplate = asyncHandler(async (req, res) => {
    const db = req.db; // ← FROM API HANDLER
    const userId = req.user.id; // ← STRING FROM JWT
    const { name, market, description, image, efficiency, risk, isFree, price, platform, botData } = req.body;

    if (!name || !market || !description || !platform) {
        console.warn("Missing required fields", { userId, route: req.originalUrl });
        res.status(400);
        throw new Error("Name, market, description, and platform are required");
    }

    if (botData && typeof botData !== "object") {
        console.warn("Invalid botData format", { userId });
        res.status(400);
        throw new Error("botData must be an object");
    }

    const template = {
        name,
        market,
        description,
        image,
        efficiency,
        risk,
        isFree: isFree ?? false,
        price: price ?? 0,
        platform,
        botData,
        createdBy: new ObjectId(userId), // ← SAFE
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    const result = await db.collection("botTemplates").insertOne(template);
    const createdTemplate = { ...template, _id: result.insertedId };

    console.info("Bot template created", { userId, templateId: createdTemplate._id });
    res.status(201).json(createdTemplate);
});

// @desc    Update a bot template
// @route   PATCH /api/bot/:id
// @access  Private/Admin
export const updateBotTemplate = asyncHandler(async (req, res) => {
    const db = req.db;
    const userId = req.user.id;
    const { id } = req.params;
    const { name, market, description, image, efficiency, risk, isFree, price, platform, botData } = req.body;

    const objectId = new ObjectId(id);
    const template = await db.collection("botTemplates").findOne({ _id: objectId });

    if (!template) {
        res.status(404);
        throw new Error("Bot template not found");
    }

    if (template.createdBy.toString() !== userId) {
        res.status(403);
        throw new Error("Not authorized to update this template");
    }

    if (botData && typeof botData !== "object") {
        res.status(400);
        throw new Error("botData must be an object");
    }

    const updateFields = { updatedAt: new Date() };
    if (name) updateFields.name = name;
    if (market) updateFields.market = market;
    if (description) updateFields.description = description;
    if (image) updateFields.image = image;
    if (efficiency !== undefined) updateFields.efficiency = efficiency;
    if (risk !== undefined) updateFields.risk = risk;
    if (isFree !== undefined) updateFields.isFree = isFree;
    if (price !== undefined) updateFields.price = price;
    if (platform) updateFields.platform = platform;
    if (botData) updateFields.botData = botData;

    const result = await db.collection("botTemplates").findOneAndUpdate(
        { _id: objectId },
        { $set: updateFields },
        { returnDocument: "after" }
    );

    console.info("Bot template updated", { userId, templateId: id });
    res.json(result.value);
});

// @desc    Get all bots with pagination
// @route   GET /api/bot
// @access  Public
export const getAllBots = asyncHandler(async (req, res) => {
    const db = req.db;
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const bots = await db.collection("botTemplates")
        .aggregate([
            {
                $lookup: {
                    from: "users",
                    localField: "createdBy",
                    foreignField: "_id",
                    as: "createdBy"
                }
            },
            { $unwind: { path: "$createdBy", preserveNullAndEmptyArrays: true } },
            { $match: { "createdBy.isActive": true, "createdBy.role": "admin" } },
            { $sort: { createdAt: -1 } },
            { $skip: skip },
            { $limit: limit },
            {
                $project: {
                    "createdBy.password": 0,
                    "createdBy.sessions": 0,
                    "createdBy.emailVerifyToken": 0,
                    "createdBy.emailVerifyExpires": 0,
                    "createdBy.deviceVerifyToken": 0,
                    "createdBy.deviceVerifyExpires": 0,
                    "createdBy.deviceVerifyFingerprint": 0,
                    "createdBy.passwordResetToken": 0,
                    "createdBy.passwordResetExpires": 0,
                }
            }
        ])
        .toArray();

    if (bots.length === 0) {
        res.status(404);
        throw new Error("No bots found");
    }

    const totalBots = await db.collection("botTemplates").countDocuments({ createdBy: { $exists: true } });

    const botResponse = bots.map(bot => ({
        id: bot._id,
        name: bot.name,
        market: bot.market,
        description: bot.description,
        image: bot.image,
        efficiency: bot.efficiency,
        risk: bot.risk,
        isFree: bot.isFree,
        price: bot.price,
        platform: bot.platform,
        botData: bot.botData,
        creator: {
            id: bot.createdBy._id,
            username: bot.createdBy.username,
            profile_image: bot.createdBy.profileImage,
            role: bot.createdBy.role,
            first_name: bot.createdBy.firstName,
            last_name: bot.createdBy.lastName,
            display_name: bot.createdBy.firstName && bot.createdBy.lastName
                ? `${bot.createdBy.firstName} ${bot.createdBy.lastName}`
                : bot.createdBy.username,
        },
        createdAt: bot.createdAt,
    }));

    console.info("Fetched all bots", { count: botResponse.length, page, limit });
    res.json({
        bots: botResponse,
        totalBots,
        currentPage: page,
        totalPages: Math.ceil(totalBots / limit),
    });
});

// @desc    Get all bots for the authenticated user
// @route   GET /api/bot/user
// @access  Private
export const getUserBots = asyncHandler(async (req, res) => {
    const db = req.db;
    const userId = new ObjectId(req.user.id);
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const userRobots = await db.collection("userrobots")
        .aggregate([
            { $match: { userId } },
            {
                $lookup: {
                    from: "botTemplates",
                    localField: "template.refId",
                    foreignField: "_id",
                    as: "template.refId"
                }
            },
            { $unwind: "$template.refId" },
            {
                $lookup: {
                    from: "users",
                    localField: "template.refId.createdBy",
                    foreignField: "_id",
                    as: "template.refId.createdBy"
                }
            },
            { $unwind: { path: "$template.refId.createdBy", preserveNullAndEmptyArrays: true } },
            { $match: { "template.refId.createdBy.isActive": true, "template.refId.createdBy.role": "admin" } },
            { $sort: { createdAt: -1 } },
            { $skip: skip },
            { $limit: limit },
        ])
        .toArray();

    if (userRobots.length === 0) {
        res.status(404);
        throw new Error("No bots found for this user");
    }

    const totalRobots = await db.collection("userrobots").countDocuments({ userId });

    const robotResponse = userRobots.map(robot => ({
        id: robot._id,
        template: {
            id: robot.template.refId._id,
            name: robot.template.refId.name,
            description: robot.template.refId.description,
            image: robot.template.refId.image,
            price: robot.template.refId.price,
            market: robot.template.refId.market,
            risk: robot.template.refId.risk,
            platform: robot.template.refId.platform,
            creator: {
                id: robot.template.refId.createdBy._id,
                username: robot.template.refId.createdBy.username,
                profile_image: robot.template.refId.createdBy.profileImage,
                display_name: robot.template.refId.createdBy.firstName && robot.template.refId.createdBy.lastName
                    ? `${robot.template.refId.createdBy.firstName} ${robot.template.refId.createdBy.lastName}`
                    : robot.template.refId.createdBy.username,
            },
        },
        config: robot.config,
        accountState: robot.accountState,
        purchased: robot.purchased,
        transactionId: robot.transactionId,
        status: robot.status,
        progress: robot.progress,
        runHistory: robot.runHistory,
        apiKeyCount: robot.apiKeys?.length || 0,
        lastUpdated: robot.lastUpdated,
        createdAt: robot.createdAt,
    }));

    console.info("Fetched user bots", { userId: req.user.id, count: robotResponse.length });
    res.json({
        bots: robotResponse,
        totalBots: totalRobots,
        currentPage: page,
        totalPages: Math.ceil(totalBots / limit),
    });
});

// @desc    Check if a bot has API keys
// @route   GET /api/bot/:botId/has-api-key
// @access  Private
export const hasApiKey = asyncHandler(async (req, res) => {
    const db = req.db;
    const userId = new ObjectId(req.user.id);
    const botId = new ObjectId(req.params.botId);

    const userRobot = await db.collection("userrobots")
        .aggregate([
            { $match: { _id: botId, userId } },
            {
                $lookup: {
                    from: "botTemplates",
                    localField: "template.refId",
                    foreignField: "_id",
                    as: "template.refId"
                }
            },
            { $unwind: "$template.refId" },
            { $project: { apiKeys: 1, "template.refId.platform": 1 } }
        ])
        .next();

    if (!userRobot) {
        return res.status(404).json({ message: "Bot not found or not owned by user" });
    }

    res.json({
        hasApiKey: !!userRobot.apiKeys?.length,
        apiKeyCount: userRobot.apiKeys?.length || 0,
        platform: userRobot.template.refId.platform,
    });
});

// @desc    Acquire a bot
// @route   POST /api/bot/acquire
// @access  Private
export const acquireBot = asyncHandler(async (req, res) => {
    const db = req.db;
    const client = req.client; // ← from API handler
    const session = client.startSession();
    await session.startTransaction();

    try {
        const userId = new ObjectId(req.user.id);
        const { templateId, config, transactionId, startMode } = req.body;
        const templateObjectId = new ObjectId(templateId);

        if (!templateObjectId || !config || typeof config !== "object") {
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid input" });
        }

        const template = await db.collection("botTemplates").findOne({ _id: templateObjectId });
        if (!template) {
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot template not found" });
        }

        if (!template.isFree && !transactionId) {
            await session.abortTransaction();
            return res.status(400).json({ message: "Transaction ID required for paid bot" });
        }

        const status = startMode === "momentarily" ? "RUNNING_MOMENTARILY" :
            startMode === "perpetually" ? "RUNNING_PERPETUALLY" : "STOPPED";

        const userRobot = {
            userId,
            template: { refId: template._id, snapshot: { ...template, createdBy: undefined } },
            config: { ...config, accountState: config.accountState || "demo" },
            apiKeys: (config.apiKeys || []).map(k => ({ platform: k.platform, data: k })),
            purchased: template.isFree || !!transactionId,
            transactionId: transactionId || null,
            status,
            accountState: config.accountState || "demo",
            runHistory: status !== "STOPPED" ? [{ action: `Started (${startMode})`, timestamp: new Date() }] : [],
            progress: {},
            lastUpdated: new Date(),
            createdAt: new Date(),
        };

        const result = await db.collection("userrobots").insertOne(userRobot, { session });
        const botId = result.insertedId;

        if (startMode && startMode !== "none") {
            const pythonConfig = { ...userRobot.config, apiKeys: userRobot.apiKeys.map(k => k.data) };
            try {
                const resp = await axios.post(
                    process.env.PYTHON_SERVER_URL + "/api/bots/update",
                    {
                        botId: botId.toString(),
                        userId: req.user.id,
                        config: pythonConfig,
                        status,
                        templateId: template._id.toString(),
                        platform: template.platform,
                        market: template.market,
                    },
                    { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
                );
                if (resp.status !== 200) throw new Error("Python server failed");
            } catch (error) {
                await session.abortTransaction();
                return res.status(500).json({ message: "Failed to start bot on Python server" });
            }
        }

        await db.collection("users").updateOne(
            { _id: userId },
            { $push: { robots: { robot_id: botId, robot_name: template.name } }, $set: { updatedAt: new Date() } },
            { session }
        );

        await session.commitTransaction();
        res.status(201).json({ message: "Bot acquired", robot: { id: botId, ...userRobot } });
    } catch (error) {
        await session.abortTransaction();
        res.status(500).json({ message: "Failed to acquire bot", error: error.message });
    } finally {
        await session.endSession();
    }
});

// @desc    Update bot config & optionally start
// @route   PATCH /api/bot/:botId
// @access  Private
export const updateUserBot = asyncHandler(async (req, res) => {
    const db = req.db;
    const client = req.client;
    const session = client.startSession();
    await session.startTransaction();

    try {
        const userId = new ObjectId(req.user.id);
        const botId = new ObjectId(req.params.botId);
        const { config, startMode } = req.body;

        if (!botId || !config) {
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid input" });
        }

        const userRobot = await db.collection("userrobots").findOne({ _id: botId, userId });
        if (!userRobot) {
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found" });
        }

        const newStatus = startMode === "momentarily" ? "RUNNING_MOMENTARILY" :
            startMode === "perpetually" ? "RUNNING_PERPETUALLY" :
                startMode === "none" ? "STOPPED" : userRobot.status;

        if (startMode && startMode !== "none") {
            const pythonConfig = { ...userRobot.config, ...config, apiKeys: (config.apiKeys || userRobot.apiKeys).map(k => k.data) };
            try {
                const resp = await axios.post(
                    process.env.PYTHON_SERVER_URL + "/api/bots/update",
                    {
                        botId: botId.toString(),
                        userId: req.user.id,
                        config: pythonConfig,
                        status: newStatus,
                        templateId: userRobot.template.refId.toString(),
                        platform: userRobot.template.snapshot.platform,
                        market: userRobot.template.snapshot.market,
                    },
                    { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
                );
                if (resp.status !== 200) throw new Error("Update failed");
            } catch {
                await session.abortTransaction();
                return res.status(500).json({ message: "Failed to update on Python server" });
            }
        }

        const updated = {
            ...userRobot,
            config: { ...userRobot.config, ...config },
            status: newStatus,
            lastUpdated: new Date(),
            apiKeys: config.apiKeys ? config.apiKeys.map(k => ({ platform: k.platform, data: k })) : userRobot.apiKeys,
        };

        if (newStatus !== userRobot.status) {
            updated.runHistory.push({ action: `Updated to ${newStatus}`, timestamp: new Date() });
        }

        await db.collection("userrobots").replaceOne({ _id: botId }, updated, { session });
        await session.commitTransaction();

        res.json({ message: "Bot updated", robot: { id: botId, ...updated } });
    } catch (error) {
        await session.abortTransaction();
        res.status(500).json({ message: "Update failed", error: error.message });
    } finally {
        await session.endSession();
    }
});

// @desc    Start bot
// @route   POST /api/bot/:botId/start
// @access  Private
export const startUserBot = asyncHandler(async (req, res) => {
    const db = req.db;
    const client = req.client;
    const session = client.startSession();
    await session.startTransaction();

    try {
        const userId = new ObjectId(req.user.id);
        const botId = new ObjectId(req.params.botId);
        const { startMode, apiKeys } = req.body;

        const userRobot = await db.collection("userrobots").findOne({ _id: botId, userId });
        if (!userRobot) {
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found" });
        }

        if (userRobot.status.includes("RUNNING")) {
            await session.abortTransaction();
            return res.status(400).json({ message: "Bot already running" });
        }

        const newStatus = startMode === "momentarily" ? "RUNNING_MOMENTARILY" : "RUNNING_PERPETUALLY";
        const finalApiKeys = apiKeys || userRobot.apiKeys;

        if (!finalApiKeys?.length) {
            await session.abortTransaction();
            return res.status(400).json({ message: "API key required to start" });
        }

        try {
            await axios.post(
                process.env.PYTHON_SERVER_URL + "/api/bots/update",
                {
                    botId: botId.toString(),
                    userId: req.user.id,
                    config: { ...userRobot.config, apiKeys: finalApiKeys.map(k => k.data) },
                    status: newStatus,
                    templateId: userRobot.template.refId.toString(),
                    platform: userRobot.template.snapshot.platform,
                    market: userRobot.template.snapshot.market,
                },
                { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
            );
        } catch {
            await session.abortTransaction();
            return res.status(500).json({ message: "Failed to start on Python server" });
        }

        await db.collection("userrobots").updateOne(
            { _id: botId },
            {
                $set: { status: newStatus, lastUpdated: new Date(), apiKeys: finalApiKeys },
                $push: { runHistory: { action: `Started (${startMode})`, timestamp: new Date() } }
            },
            { session }
        );

        await session.commitTransaction();
        res.json({ message: "Bot started", status: newStatus });
    } catch (error) {
        await session.abortTransaction();
        res.status(500).json({ message: "Start failed", error: error.message });
    } finally {
        await session.endSession();
    }
});

// @desc    Stop bot
// @route   POST /api/bot/:botId/stop
// @access  Private
export const stopUserBot = asyncHandler(async (req, res) => {
    const db = req.db;
    const client = req.client;
    const session = client.startSession();
    await session.startTransaction();

    try {
        const userId = new ObjectId(req.user.id);
        const botId = new ObjectId(req.params.botId);
        const { stopMode } = req.body;

        const userRobot = await db.collection("userrobots").findOne({ _id: botId, userId });
        if (!userRobot) {
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found" });
        }

        const newStatus = stopMode === "pause" ? "PAUSED" : "STOPPED";

        try {
            await axios.post(
                process.env.PYTHON_SERVER_URL + "/api/bots/update",
                {
                    botId: botId.toString(),
                    userId: req.user.id,
                    config: { ...userRobot.config, apiKeys: userRobot.apiKeys.map(k => k.data) },
                    status: newStatus,
                    templateId: userRobot.template.refId.toString(),
                    platform: userRobot.template.snapshot.platform,
                    market: userRobot.template.snapshot.market,
                },
                { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
            );
        } catch {
            await session.abortTransaction();
            return res.status(500).json({ message: "Failed to stop on Python server" });
        }

        await db.collection("userrobots").updateOne(
            { _id: botId },
            {
                $set: { status: newStatus, lastUpdated: new Date() },
                $push: { runHistory: { action: stopMode === "pause" ? "Paused" : "Stopped", timestamp: new Date() } }
            },
            { session }
        );

        await session.commitTransaction();
        res.json({ message: "Bot stopped", status: newStatus });
    } catch (error) {
        await session.abortTransaction();
        res.status(500).json({ message: "Stop failed", error: error.message });
    } finally {
        await session.endSession();
    }
});

// @desc    Delete bot
// @route   DELETE /api/bot/:botId
// @access  Private
export const deleteUserBot = asyncHandler(async (req, res) => {
    const db = req.db;
    const client = req.client;
    const session = client.startSession();
    await session.startTransaction();

    try {
        const userId = new ObjectId(req.user.id);
        const botId = new ObjectId(req.params.botId);

        const userRobot = await db.collection("userrobots").findOne({ _id: botId, userId });
        if (!userRobot) {
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found" });
        }

        try {
            await axios.post(
                process.env.PYTHON_SERVER_URL + "/api/bots/delete",
                { botId: botId.toString(), userId: req.user.id, templateId: userRobot.template.refId.toString() },
                { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
            );
        } catch {
            await session.abortTransaction();
            return res.status(500).json({ message: "Failed to delete on Python server" });
        }

        await db.collection("userrobots").deleteOne({ _id: botId }, { session });
        await db.collection("users").updateOne(
            { _id: userId },
            { $pull: { robots: { robot_id: botId } } },
            { session }
        );

        await session.commitTransaction();
        res.json({ message: "Bot deleted" });
    } catch (error) {
        await session.abortTransaction();
        res.status(500).json({ message: "Delete failed", error: error.message });
    } finally {
        await session.endSession();
    }
});

// @desc    Update bot progress (from Python)
// @route   POST /api/bot/:botId/progress
// @access  Private (Python)
export const updateBotProgress = asyncHandler(async (req, res) => {
    const db = req.db;
    const client = req.client;
    const session = client.startSession();
    await session.startTransaction();

    try {
        const botId = new ObjectId(req.params.botId);
        const { progress } = req.body;

        if (!botId || !progress) {
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid input" });
        }

        const update = {
            $set: { progress, lastUpdated: new Date() },
            $push: { runHistory: { action: "Progress Updated", timestamp: new Date(), progressSnapshot: progress } }
        };

        const result = await db.collection("userrobots").updateOne({ _id: botId }, update, { session });
        if (result.matchedCount === 0) {
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found" });
        }

        await session.commitTransaction();
        res.json({ message: "Progress updated", progress });
    } catch (error) {
        await session.abortTransaction();
        res.status(500).json({ message: "Progress update failed", error: error.message });
    } finally {
        await session.endSession();
    }
});