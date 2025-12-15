// src/controllers/botController.js
import asyncHandler from "express-async-handler";
import axios from "axios";
import BotTemplate from "../models/botTemplateModel.js";
import UserRobot from "../models/userRobotModel.js";
import Users from "../models/userModel.js";

export const createBotTemplate = asyncHandler(async (req, res) => {
    const userId = req.user.id;
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

    const template = await BotTemplate.create({
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
        createdBy: userId,
    });

    console.info("Bot template created", { userId, templateId: template._id });
    res.status(201).json(template);
});

export const updateBotTemplate = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { id } = req.params;
    const { name, market, description, image, efficiency, risk, isFree, price, platform, botData } = req.body;

    const template = await BotTemplate.findById(id);

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

    const updateFields = {};
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

    const updatedTemplate = await BotTemplate.findByIdAndUpdate(
        id,
        { $set: updateFields },
        { new: true, runValidators: true }
    );

    console.info("Bot template updated", { userId, templateId: id });
    res.json(updatedTemplate);
});

export const getAllBots = asyncHandler(async (req, res) => {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const bots = await BotTemplate.find({})
        .populate({
            path: 'createdBy',
            select: '-password -sessions -emailVerifyToken -deviceVerifyToken -passwordResetToken -__v',
            match: { isActive: true, role: 'admin' }
        })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);

    if (bots.length === 0) {
        return res.status(404).json({
            success: false,
            message: "No bots found"
        });
    }

    const filteredBots = bots.filter(bot => bot.createdBy);

    if (filteredBots.length === 0) {
        return res.status(404).json({
            success: false,
            message: "No active admin bots available"
        });
    }

    const botResponse = filteredBots.map(bot => ({
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
            display_name: bot.createdBy.firstName && bot.createdBy.lastName
                ? `${bot.createdBy.firstName} ${bot.createdBy.lastName}`
                : bot.createdBy.username,
        },
        createdAt: bot.createdAt,
    }));

    const totalBots = await BotTemplate.countDocuments();

    console.info("Fetched all bots", { count: botResponse.length, page, limit });
    res.json({
        success: true,
        bots: botResponse,
        totalBots,
        currentPage: page,
        totalPages: Math.ceil(totalBots / limit),
    });
});

export const getUserBots = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const userRobots = await UserRobot.find({ userId })
        .populate({
            path: 'template.refId',
            populate: {
                path: 'createdBy',
                select: '-password -sessions -emailVerifyToken -deviceVerifyToken -passwordResetToken -__v',
                match: { isActive: true, role: 'admin' }
            }
        })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);

    if (userRobots.length === 0) {
        return res.status(404).json({
            success: false,
            message: "No bots found for this user"
        });
    }

    const filteredRobots = userRobots.filter(robot =>
        robot.template.refId && robot.template.refId.createdBy
    );

    if (filteredRobots.length === 0) {
        return res.status(404).json({
            success: false,
            message: "No valid bots found for this user"
        });
    }

    const robotResponse = filteredRobots.map(robot => ({
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

    const totalRobots = await UserRobot.countDocuments({ userId });

    console.info("Fetched user bots", { userId, count: robotResponse.length });
    res.json({
        success: true,
        bots: robotResponse,
        totalBots: totalRobots,
        currentPage: page,
        totalPages: Math.ceil(totalRobots / limit),
    });
});

export const hasApiKey = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { botId } = req.params;

    const userRobot = await UserRobot.findOne({ _id: botId, userId })
        .populate('template.refId', 'platform');

    if (!userRobot) {
        return res.status(404).json({
            success: false,
            message: "Bot not found or not owned by user"
        });
    }

    res.json({
        success: true,
        hasApiKey: !!userRobot.apiKeys?.length,
        apiKeyCount: userRobot.apiKeys?.length || 0,
        platform: userRobot.template.refId.platform,
    });
});

export const acquireBot = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { templateId, config, transactionId, startMode } = req.body;

    if (!templateId || !config || typeof config !== "object") {
        return res.status(400).json({
            success: false,
            message: "Invalid input"
        });
    }

    const template = await BotTemplate.findById(templateId);
    if (!template) {
        return res.status(404).json({
            success: false,
            message: "Bot template not found"
        });
    }

    if (!template.isFree && !transactionId) {
        return res.status(400).json({
            success: false,
            message: "Transaction ID required for paid bot"
        });
    }

    const status = startMode === "momentarily" ? "running momentarily" :
        startMode === "perpetually" ? "running perpetually" : "stopped";

    const userRobot = await UserRobot.create({
        userId,
        template: {
            refId: template._id,
            snapshot: {
                name: template.name,
                description: template.description,
                image: template.image,
                price: template.price,
                market: template.market,
                risk: template.risk,
                platform: template.platform
            }
        },
        config: { ...config, accountState: config.accountState || "demo" },
        apiKeys: (config.apiKeys || []).map(k => ({ platform: k.platform, data: k })),
        purchased: template.isFree || !!transactionId,
        transactionId: transactionId || null,
        status,
        accountState: config.accountState || "demo",
        runHistory: status !== "stopped" ? [{ action: `Started (${startMode})`, timestamp: new Date() }] : [],
        progress: {},
    });

    await Users.findByIdAndUpdate(
        userId,
        {
            $push: {
                robots: {
                    robot_id: userRobot._id,
                    robot_name: template.name
                }
            }
        }
    );

    if (startMode && startMode !== "none") {
        try {
            await axios.post(
                process.env.PYTHON_SERVER_URL + "/api/bots/update",
                {
                    botId: userRobot._id.toString(),
                    userId: userId,
                    config: { ...config, apiKeys: config.apiKeys || [] },
                    status,
                    templateId: template._id.toString(),
                    platform: template.platform,
                    market: template.market,
                },
                {
                    headers: {
                        Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}`
                    }
                }
            );
        } catch (error) {
            console.error("Python server call failed:", error.message);
        }
    }

    res.status(201).json({
        success: true,
        message: "Bot acquired",
        robot: userRobot
    });
});

export const updateUserBot = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { botId } = req.params;
    const { config, startMode } = req.body;

    if (!botId || !config) {
        return res.status(400).json({ message: "Invalid input" });
    }

    const userRobot = await UserRobot.findOne({ _id: botId, userId });
    if (!userRobot) {
        return res.status(404).json({ message: "Bot not found" });
    }

    const newStatus = startMode === "momentarily" ? "running momentarily" :
        startMode === "perpetually" ? "running perpetually" :
            startMode === "none" ? "stopped" : userRobot.status;

    if (startMode && startMode !== "none") {
        try {
            const resp = await axios.post(
                process.env.PYTHON_SERVER_URL + "/api/bots/update",
                {
                    botId: botId.toString(),
                    userId: userId,
                    config: { ...userRobot.config, ...config, apiKeys: (config.apiKeys || userRobot.apiKeys).map(k => k.data) },
                    status: newStatus,
                    templateId: userRobot.template.refId.toString(),
                    platform: userRobot.template.snapshot.platform,
                    market: userRobot.template.snapshot.market,
                },
                { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
            );
            if (resp.status !== 200) throw new Error("Update failed");
        } catch {
            return res.status(500).json({ message: "Failed to update on Python server" });
        }
    }

    const updated = {
        ...userRobot.toObject(),
        config: { ...userRobot.config, ...config },
        status: newStatus,
        lastUpdated: new Date(),
        apiKeys: config.apiKeys ? config.apiKeys.map(k => ({ platform: k.platform, data: k })) : userRobot.apiKeys,
    };

    if (newStatus !== userRobot.status) {
        updated.runHistory.push({ action: `Updated to ${newStatus}`, timestamp: new Date() });
    }

    await UserRobot.findByIdAndUpdate(botId, updated);

    res.json({ message: "Bot updated", robot: { id: botId, ...updated } });
});

export const startUserBot = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { botId } = req.params;
    const { startMode, apiKeys } = req.body;

    const userRobot = await UserRobot.findOne({ _id: botId, userId });
    if (!userRobot) {
        return res.status(404).json({ message: "Bot not found" });
    }

    if (userRobot.status.includes("running")) {
        return res.status(400).json({ message: "Bot already running" });
    }

    const newStatus = startMode === "momentarily" ? "running momentarily" : "running perpetually";
    const finalApiKeys = apiKeys || userRobot.apiKeys;

    if (!finalApiKeys?.length) {
        return res.status(400).json({ message: "API key required to start" });
    }

    try {
        await axios.post(
            process.env.PYTHON_SERVER_URL + "/api/bots/update",
            {
                botId: botId.toString(),
                userId: userId,
                config: { ...userRobot.config, apiKeys: finalApiKeys.map(k => k.data) },
                status: newStatus,
                templateId: userRobot.template.refId.toString(),
                platform: userRobot.template.snapshot.platform,
                market: userRobot.template.snapshot.market,
            },
            { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
        );
    } catch {
        return res.status(500).json({ message: "Failed to start on Python server" });
    }

    await UserRobot.findByIdAndUpdate(
        botId,
        {
            $set: { status: newStatus, lastUpdated: new Date(), apiKeys: finalApiKeys },
            $push: { runHistory: { action: `Started (${startMode})`, timestamp: new Date() } }
        }
    );

    res.json({ message: "Bot started", status: newStatus });
});

export const stopUserBot = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { botId } = req.params;
    const { stopMode } = req.body;

    const userRobot = await UserRobot.findOne({ _id: botId, userId });
    if (!userRobot) {
        return res.status(404).json({ message: "Bot not found" });
    }

    const newStatus = stopMode === "pause" ? "paused" : "stopped";

    try {
        await axios.post(
            process.env.PYTHON_SERVER_URL + "/api/bots/update",
            {
                botId: botId.toString(),
                userId: userId,
                config: { ...userRobot.config, apiKeys: userRobot.apiKeys.map(k => k.data) },
                status: newStatus,
                templateId: userRobot.template.refId.toString(),
                platform: userRobot.template.snapshot.platform,
                market: userRobot.template.snapshot.market,
            },
            { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
        );
    } catch {
        return res.status(500).json({ message: "Failed to stop on Python server" });
    }

    await UserRobot.findByIdAndUpdate(
        botId,
        {
            $set: { status: newStatus, lastUpdated: new Date() },
            $push: { runHistory: { action: stopMode === "pause" ? "Paused" : "Stopped", timestamp: new Date() } }
        }
    );

    res.json({ message: "Bot stopped", status: newStatus });
});

export const deleteUserBot = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { botId } = req.params;

    const userRobot = await UserRobot.findOne({ _id: botId, userId });
    if (!userRobot) {
        return res.status(404).json({ message: "Bot not found" });
    }

    try {
        await axios.post(
            process.env.PYTHON_SERVER_URL + "/api/bots/delete",
            { botId: botId.toString(), userId: userId, templateId: userRobot.template.refId.toString() },
            { headers: { Authorization: `Bearer ${process.env.PYTHON_SERVER_API_KEY}` } }
        );
    } catch {
        return res.status(500).json({ message: "Failed to delete on Python server" });
    }

    await UserRobot.findByIdAndDelete(botId);
    await Users.findByIdAndUpdate(
        userId,
        { $pull: { robots: { robot_id: botId } } }
    );

    res.json({ message: "Bot deleted" });
});

export const updateBotProgress = asyncHandler(async (req, res) => {
    const { botId } = req.params;
    const { progress } = req.body;

    if (!botId || !progress) {
        return res.status(400).json({ message: "Invalid input" });
    }

    const update = {
        $set: { progress, lastUpdated: new Date() },
        $push: { runHistory: { action: "Progress Updated", timestamp: new Date(), progressSnapshot: progress } }
    };

    const result = await UserRobot.findByIdAndUpdate(botId, update);
    if (!result) {
        return res.status(404).json({ message: "Bot not found" });
    }

    res.json({ message: "Progress updated", progress });
});