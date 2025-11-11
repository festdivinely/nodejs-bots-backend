import mongoose from "mongoose";
import asyncHandler from "express-async-handler";
import BotTemplate from "../models/botTemplateModel.js";
import UserRobot from "../models/userBotsModel.js";
import User from "../models/userModel.js";
import { BotStatus } from "../models/userBotsModel.js";
import axios from "axios";
import cloudinary from "../config/cloudinarydb.js";

// @desc    Create a new bot template
// @route   POST /api/templates
// @access  Private/Admin
export const createBotTemplate = asyncHandler(async (req, res) => {
    const { name, market, description, image, efficiency, risk, isFree, price, platform, botData } = req.body;

    // Validation
    if (!name || !market || !description || !platform) {
        console.warn("Missing required fields for bot template creation", { userId: req.user.id, route: req.originalUrl });
        res.status(400);
        throw new Error("Name, market, description, and platform are required");
    }

    if (botData && typeof botData !== "object") {
        console.warn("Invalid botData format", { userId: req.user.id, route: req.originalUrl });
        res.status(400);
        throw new Error("botData must be an object");
    }

    const template = new BotTemplate({
        name,
        market,
        description,
        image,
        efficiency,
        risk,
        isFree,
        price,
        platform,
        botData,
        createdBy: req.user.id,
    });

    const createdTemplate = await template.save();
    console.info("Bot template created successfully", { userId: req.user.id, templateId: createdTemplate._id, route: req.originalUrl });

    res.status(201).json(createdTemplate);
});

// @desc    Update a bot template
// @route   PATCH /api/templates/:id
// @access  Private/Admin
export const updateBotTemplate = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { name, market, description, image, efficiency, risk, isFree, price, platform, botData } = req.body;

    const template = await BotTemplate.findById(id);

    if (!template) {
        console.warn("Bot template not found", { userId: req.user.id, templateId: id, route: req.originalUrl });
        res.status(404);
        throw new Error("Bot template not found");
    }

    if (template.createdBy.toString() !== req.user.id) {
        console.warn("Unauthorized attempt to update bot template", { userId: req.user.id, templateId: id, route: req.originalUrl });
        res.status(403);
        throw new Error("Not authorized to update this template");
    }

    if (botData && typeof botData !== "object") {
        console.warn("Invalid botData format for update", { userId: req.user.id, templateId: id, route: req.originalUrl });
        res.status(400);
        throw new Error("botData must be an object");
    }

    if (name) template.name = name;
    if (market) template.market = market;
    if (description) template.description = description;
    if (image) template.image = image;
    if (efficiency) template.efficiency = efficiency;
    if (risk) template.risk = risk;
    if (isFree !== undefined) template.isFree = isFree;
    if (price !== undefined) template.price = price;
    if (platform) template.platform = platform;
    if (botData) template.botData = botData;

    const updatedTemplate = await template.save();
    console.info("Bot template updated successfully", { userId: req.user.id, templateId: id, route: req.originalUrl });

    res.json(updatedTemplate);
});

// @desc    Get all bots with pagination
// @route   GET /api/bots
// @access  Public
export const getAllBots = asyncHandler(async (req, res) => {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const bots = await BotTemplate.find()
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate({
            path: "createdBy",
            select: "username profile_image role first_name last_name is_active",
            match: { is_active: true, role: "admin" },
        });

    if (!bots || bots.length === 0) {
        console.warn("No bots found", { route: req.originalUrl });
        res.status(404);
        throw new Error("No bots found");
    }

    const filteredBots = bots.filter((bot) => bot.createdBy);
    const totalBots = await BotTemplate.countDocuments({
        createdBy: { $exists: true },
    });

    const botResponse = filteredBots.map((bot) => ({
        id: bot.id,
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
            id: bot.createdBy.id,
            username: bot.createdBy.username,
            profile_image: bot.createdBy.profile_image,
            role: bot.createdBy.role,
            first_name: bot.createdBy.first_name,
            last_name: bot.createdBy.last_name,
            display_name: bot.createdBy.first_name && bot.createdBy.last_name
                ? `${bot.createdBy.first_name} ${bot.createdBy.last_name}`
                : bot.createdBy.username,
        },
        createdAt: bot.createdAt,
    }));

    console.info("Fetched all bots", { totalBots: botResponse.length, page, limit, route: req.originalUrl });
    res.status(200).json({
        bots: botResponse,
        totalBots,
        currentPage: page,
        totalPages: Math.ceil(totalBots / limit),
    });
});

// @desc    Get all bots for the authenticated user
// @route   GET /api/user/bots
// @access  Private
export const getUserBots = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const userRobots = await UserRobot.find({ userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate({
            path: "template.refId",
            select: "name description image price market risk platform createdBy",
            populate: {
                path: "createdBy",
                select: "username profile_image first_name last_name role",
                match: { is_active: true, role: "admin" },
            },
        });

    if (!userRobots || userRobots.length === 0) {
        console.warn("No bots found for user", { userId, route: req.originalUrl });
        res.status(404);
        throw new Error("No bots found for this user");
    }

    const filteredRobots = userRobots.filter((robot) => robot.template.refId && robot.template.refId.createdBy);
    const totalRobots = await UserRobot.countDocuments({ userId });

    const robotResponse = filteredRobots.map((robot) => ({
        id: robot.id,
        template: {
            id: robot.template.refId.id,
            name: robot.template.refId.name,
            description: robot.template.refId.description,
            image: robot.template.refId.image,
            price: robot.template.refId.price,
            market: robot.template.refId.market,
            risk: robot.template.refId.risk,
            platform: robot.template.refId.platform,
            creator: {
                id: robot.template.refId.createdBy.id,
                username: robot.template.refId.createdBy.username,
                profile_image: robot.template.refId.createdBy.profile_image,
                display_name: robot.template.refId.createdBy.first_name && robot.template.refId.createdBy.last_name
                    ? `${robot.template.refId.first_name} ${robot.template.refId.last_name}`
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
        apiKeyCount: robot.apiKeys ? robot.apiKeys.length : 0,
        lastUpdated: robot.lastUpdated,
        createdAt: robot.createdAt,
    }));

    console.info("Fetched user bots", { userId, totalBots: robotResponse.length, page, limit, route: req.originalUrl });
    res.status(200).json({
        bots: robotResponse,
        totalBots: totalRobots,
        currentPage: page,
        totalPages: Math.ceil(totalRobots / limit),
    });
});

// @desc    Check if a bot has API keys and return the expected platform
// @route   GET /api/user/bots/:botId/has-api-key
// @access  Private
export const hasApiKey = asyncHandler(async (req, res) => {
    const { botId } = req.params;
    const userId = req.user.id;

    if (!botId || !mongoose.isValidObjectId(botId)) {
        console.warn("Invalid or missing botId for API key check", { userId, botId, route: req.originalUrl });
        return res.status(400).json({ message: "Invalid or missing botId" });
    }

    const userRobot = await UserRobot.findOne({ _id: botId, userId })
        .populate("template.refId", "platform");
    if (!userRobot) {
        console.warn("Bot not found or not owned by user", { userId, botId, route: req.originalUrl });
        return res.status(404).json({ message: "Bot not found or not owned by user" });
    }

    console.info("Checked API key status for bot", { userId, botId, route: req.originalUrl });
    return res.status(200).json({
        hasApiKey: userRobot.apiKeys && userRobot.apiKeys.length > 0,
        apiKeyCount: userRobot.apiKeys ? userRobot.apiKeys.length : 0,
        platform: userRobot.template.refId.platform,
    });
});

// @desc    Acquire a bot for the authenticated user
// @route   POST /api/user/bots
// @access  Private
export const acquireBot = asyncHandler(async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const userId = req.user.id;
        const { templateId, config, transactionId, startMode } = req.body;

        // Validate inputs
        if (!templateId || !mongoose.isValidObjectId(templateId)) {
            console.warn("Invalid or missing templateId for bot acquisition", { userId, templateId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing templateId" });
        }
        if (!config || typeof config !== "object" || config === null) {
            console.warn("Invalid or missing config for bot acquisition", { userId, templateId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing config" });
        }
        if ("risk_level" in config && (typeof config.risk_level !== "number" || config.risk_level < 0 || config.risk_level > 100)) {
            console.warn("Invalid risk_level for bot acquisition", { userId, templateId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "risk_level must be a number between 0 and 100" });
        }
        if (!config.accountState || !Object.values(AccountState).includes(config.accountState)) {
            console.warn("Invalid accountState for bot acquisition", { userId, templateId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "accountState must be 'demo' or 'real'" });
        }
        if (startMode && !["momentarily", "perpetually", "none"].includes(startMode)) {
            console.warn("Invalid startMode for bot acquisition", { userId, templateId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid startMode" });
        }

        const template = await BotTemplate.findById(templateId).session(session);
        if (!template) {
            console.warn("Bot template not found for acquisition", { userId, templateId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot template not found" });
        }

        const user = await User.findById(userId).session(session);
        if (!user) {
            console.warn("User not found for bot acquisition", { userId, templateId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(404).json({ message: "User not found" });
        }

        if (!template.isFree && !transactionId) {
            console.warn("Transaction ID required for paid bot", { userId, templateId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Transaction ID required for paid bot" });
        }

        // Validate apiKeys for acquire & start
        if (startMode && startMode !== "none") {
            if (!config.apiKeys || !Array.isArray(config.apiKeys) || config.apiKeys.length === 0 || config.apiKeys.some((key) => key.platform !== template.platform)) {
                console.warn("Invalid API keys for bot start", { userId, templateId, route: req.originalUrl });
                await session.abortTransaction();
                return res.status(400).json({ message: `At least one API key for the platform '${template.platform}' is required for acquire & start` });
            }
        } else if (config.apiKeys && config.apiKeys.length > 0) {
            if (config.apiKeys.some((key) => key.platform !== template.platform)) {
                console.warn("API keys platform mismatch", { userId, templateId, route: req.originalUrl });
                await session.abortTransaction();
                return res.status(400).json({ message: `All API keys must be for the platform '${template.platform}'` });
            }
        }

        const status = startMode === "momentarily" ? BotStatus.RUNNING_MOMENTARILY :
            startMode === "perpetually" ? BotStatus.RUNNING_PERPETUALLY :
                BotStatus.STOPPED;

        const userRobot = new UserRobot({
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
                    platform: template.platform,
                },
            },
            config: {
                risk_level: config.risk_level,
                accountState: config.accountState,
                ...config,
            },
            apiKeys: config.apiKeys ? config.apiKeys.map((key) => ({
                platform: key.platform,
                data: key,
            })) : [],
            purchased: template.isFree ? true : !!transactionId,
            transactionId: transactionId || null,
            status,
            accountState: config.accountState,
            runHistory: status !== BotStatus.STOPPED ? [{
                action: `Started (${startMode})`,
                timestamp: new Date(),
            }] : [],
        });

        await userRobot.save({ session });

        // Send to Python backend if starting
        if (startMode && startMode !== "none") {
            const pythonConfig = {
                ...userRobot.config,
                apiKeys: userRobot.getDecryptedApiKeys(),
            };

            try {
                const pythonServerResponse = await axios.post(
                    process.env.PYTHON_SERVER_URL + "/api/bots/update",
                    {
                        botId: userRobot._id.toString(),
                        userId: userId,
                        config: pythonConfig,
                        status: userRobot.status,
                        templateId: userRobot.template.refId.toString(),
                        platform: template.platform,
                        market: template.market,
                    },
                    {
                        headers: {
                            "Content-Type": "application/json",
                            "Authorization": `Bearer ${process.env.PYTHON_SERVER_API_KEY}`,
                        },
                    }
                );

                if (pythonServerResponse.status !== 200) {
                    console.error("Failed to process bot on Python server", {
                        userId,
                        botId: userRobot._id,
                        templateId,
                        route: req.originalUrl,
                        status: pythonServerResponse.status,
                    });
                    await session.abortTransaction();
                    return res.status(pythonServerResponse.status).json({
                        message: pythonServerResponse.data.message || "Failed to process bot on Python server",
                    });
                }
            } catch (error) {
                console.error("Failed to communicate with Python server for bot acquisition", {
                    userId,
                    botId: userRobot._id,
                    templateId,
                    route: req.originalUrl,
                    error: error.response ? error.response.data.message : error.message,
                });
                await session.abortTransaction();
                return res.status(500).json({
                    message: "Failed to communicate with Python server",
                    error: error.response ? error.response.data.message : error.message,
                });
            }
        }

        await User.findByIdAndUpdate(
            userId,
            {
                $push: {
                    robots: {
                        robot_id: userRobot._id,
                        robot_name: template.name,
                    },
                },
                $set: { updated_at: new Date() },
            },
            { session }
        );

        await session.commitTransaction();
        console.info("Bot acquired successfully", { userId, botId: userRobot._id, templateId, route: req.originalUrl });

        return res.status(201).json({
            message: "Bot acquired successfully",
            robot: {
                id: userRobot.id,
                template: userRobot.template,
                config: userRobot.config,
                accountState: userRobot.accountState,
                purchased: userRobot.purchased,
                status: userRobot.status,
                progress: userRobot.progress,
                runHistory: userRobot.runHistory,
                apiKeyCount: userRobot.apiKeys ? userRobot.apiKeys.length : 0,
            },
        });
    } catch (error) {
        console.error("Failed to acquire bot", { userId: req.user.id, templateId: req.body.templateId, route: req.originalUrl, error: error.message });
        await session.abortTransaction();
        return res.status(500).json({
            message: "Failed to acquire bot",
            error: error.message,
        });
    } finally {
        session.endSession();
    }
});

// @desc    Update a bot's configuration and optionally start/restart
// @route   PATCH /api/user/bots/:botId
// @access  Private
export const updateUserBot = asyncHandler(async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const userId = req.user.id;
        const { botId } = req.params;
        const { config, startMode } = req.body;

        // Validate inputs
        if (!botId || !mongoose.isValidObjectId(botId)) {
            console.warn("Invalid or missing botId for bot update", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing botId" });
        }
        if (!config || typeof config !== "object" || config === null) {
            console.warn("Invalid or missing config for bot update", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing config" });
        }
        if ("risk_level" in config && (typeof config.risk_level !== "number" || config.risk_level < 0 || config.risk_level > 100)) {
            console.warn("Invalid risk_level for bot update", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "risk_level must be a number between 0 and 100" });
        }
        if ("accountState" in config && !Object.values(AccountState).includes(config.accountState)) {
            console.warn("Invalid accountState for bot update", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "accountState must be 'demo' or 'real'" });
        }
        if (startMode && !["momentarily", "perpetually", "none"].includes(startMode)) {
            console.warn("Invalid startMode for bot update", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid startMode" });
        }

        const userRobot = await UserRobot.findOne({ _id: botId, userId })
            .populate("template.refId", "platform market")
            .session(session);
        if (!userRobot) {
            console.warn("Bot not found or not owned by user for update", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found or not owned by user" });
        }

        const isRunning = [BotStatus.RUNNING_MOMENTARILY, BotStatus.RUNNING_PERPETUALLY].includes(userRobot.status);

        // Validate apiKeys if provided
        if (config.apiKeys && config.apiKeys.length > 0) {
            if (config.apiKeys.some((key) => key.platform !== userRobot.template.refId.platform)) {
                console.warn("API keys platform mismatch for bot update", { userId, botId, route: req.originalUrl });
                await session.abortTransaction();
                return res.status(400).json({ message: `All API keys must be for the platform '${userRobot.template.refId.platform}'` });
            }
        }

        // For update & start (non-running bot), require at least one API key if none exist
        if (startMode && startMode !== "none" && !isRunning && (!userRobot.apiKeys || userRobot.apiKeys.length === 0)) {
            if (!config.apiKeys || config.apiKeys.length === 0 || config.apiKeys.some((key) => key.platform !== userRobot.template.refId.platform)) {
                console.warn("Invalid API keys for bot start", { userId, botId, route: req.originalUrl });
                await session.abortTransaction();
                return res.status(400).json({ message: `At least one API key for the platform '${userRobot.template.refId.platform}' is required for update & start` });
            }
        }

        // For update & restart (running bot), API keys are optional
        if (isRunning && startMode && startMode !== "none" && (!userRobot.apiKeys || userRobot.apiKeys.length === 0)) {
            console.error("Running bot missing API keys", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(500).json({ message: "Running bot must have at least one API key" });
        }

        const tempConfig = {
            ...userRobot.config,
            ...config,
            accountState: config.accountState || userRobot.accountState,
        };
        const newStatus = startMode === "momentarily" ? BotStatus.RUNNING_MOMENTARILY :
            startMode === "perpetually" ? BotStatus.RUNNING_PERPETUALLY :
                startMode === "none" ? BotStatus.STOPPED : userRobot.status;

        // Send to Python backend if bot is running or startMode is set
        const shouldSendToPython = isRunning || (startMode && startMode !== "none");
        if (shouldSendToPython) {
            const pythonConfig = {
                ...tempConfig,
                apiKeys: config.apiKeys ? config.apiKeys.map((key) => ({ platform: key.platform, ...key })) : userRobot.getDecryptedApiKeys(),
            };

            try {
                const pythonServerResponse = await axios.post(
                    process.env.PYTHON_SERVER_URL + "/api/bots/update",
                    {
                        botId: userRobot._id.toString(),
                        userId: userId,
                        config: pythonConfig,
                        status: newStatus,
                        templateId: userRobot.template.refId.toString(),
                        platform: userRobot.template.refId.platform,
                        market: userRobot.template.refId.market,
                    },
                    {
                        headers: {
                            "Content-Type": "application/json",
                            "Authorization": `Bearer ${process.env.PYTHON_SERVER_API_KEY}`,
                        },
                    }
                );

                if (pythonServerResponse.status !== 200) {
                    console.error("Failed to update bot on Python server", {
                        userId,
                        botId,
                        route: req.originalUrl,
                        status: pythonServerResponse.status,
                    });
                    await session.abortTransaction();
                    return res.status(pythonServerResponse.status).json({
                        message: pythonServerResponse.data.message || "Failed to update bot on Python server",
                    });
                }
            } catch (error) {
                console.error("Failed to communicate with Python server for bot update", {
                    userId,
                    botId,
                    route: req.originalUrl,
                    error: error.response ? error.response.data.message : error.message,
                });
                await session.abortTransaction();
                return res.status(500).json({
                    message: "Failed to communicate with Python server",
                    error: error.response ? error.response.data.message : error.message,
                });
            }
        }

        // Update bot in database
        userRobot.config = tempConfig;
        userRobot.status = newStatus;
        userRobot.accountState = tempConfig.accountState;
        if (config.apiKeys && config.apiKeys.length > 0) {
            userRobot.apiKeys = config.apiKeys.map((key) => ({
                platform: key.platform,
                data: key,
            }));
        }
        userRobot.lastUpdated = new Date();
        if (userRobot.status !== userRobot.status || shouldSendToPython) {
            userRobot.runHistory.push({
                action: newStatus === BotStatus.STOPPED ? "Stopped" :
                    isRunning ? `Updated and Restarted (${newStatus.split(" ")[1]})` :
                        `Started (${startMode})`,
                timestamp: new Date(),
            });
        }
        userRobot.markModified("config");
        userRobot.markModified("apiKeys");

        await userRobot.save({ session });
        await session.commitTransaction();

        const populatedRobot = await UserRobot.findById(botId)
            .populate({
                path: "template.refId",
                select: "name description image price market risk platform createdBy",
                populate: {
                    path: "createdBy",
                    select: "username profile_image first_name last_name role",
                    match: { is_active: true, role: "admin" },
                },
            });

        const robotResponse = {
            id: populatedRobot.id,
            template: {
                id: populatedRobot.template.refId.id,
                name: populatedRobot.template.refId.name,
                description: populatedRobot.template.refId.description,
                image: populatedRobot.template.refId.image,
                price: populatedRobot.template.refId.price,
                market: populatedRobot.template.refId.market,
                risk: populatedRobot.template.refId.risk,
                platform: populatedRobot.template.refId.platform,
                creator: {
                    id: populatedRobot.template.refId.createdBy.id,
                    username: populatedRobot.template.refId.createdBy.username,
                    profile_image: populatedRobot.template.refId.createdBy.profile_image,
                    display_name: populatedRobot.template.refId.createdBy.first_name && populatedRobot.template.refId.createdBy.last_name
                        ? `${populatedRobot.template.refId.first_name} ${populatedRobot.template.refId.last_name}`
                        : populatedRobot.template.refId.createdBy.username,
                },
            },
            config: populatedRobot.config,
            accountState: populatedRobot.accountState,
            purchased: populatedRobot.purchased,
            transactionId: populatedRobot.transactionId,
            status: populatedRobot.status,
            progress: populatedRobot.progress,
            runHistory: populatedRobot.runHistory,
            apiKeyCount: populatedRobot.apiKeys ? populatedRobot.apiKeys.length : 0,
            lastUpdated: populatedRobot.lastUpdated,
            createdAt: populatedRobot.createdAt,
        };

        console.info("Bot updated successfully", { userId, botId, route: req.originalUrl });
        return res.status(200).json({
            message: "Bot updated successfully",
            robot: robotResponse,
        });
    } catch (error) {
        console.error("Failed to update bot", { userId: req.user.id, botId: req.params.botId, route: req.originalUrl, error: error.message });
        await session.abortTransaction();
        return res.status(500).json({
            message: "Failed to update bot",
            error: error.message,
        });
    } finally {
        session.endSession();
    }
});

// @desc    Start a bot
// @route   POST /api/user/bots/:botId/start
// @access  Private
export const startUserBot = asyncHandler(async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const userId = req.user.id;
        const { botId } = req.params;
        const { startMode, apiKeys } = req.body;

        // Validate inputs
        if (!botId || !mongoose.isValidObjectId(botId)) {
            console.warn("Invalid or missing botId for bot start", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing botId" });
        }
        if (!startMode || !["momentarily", "perpetually"].includes(startMode)) {
            console.warn("Invalid or missing startMode for bot start", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing startMode" });
        }

        const userRobot = await UserRobot.findOne({ _id: botId, userId })
            .populate("template.refId", "platform market")
            .session(session);
        if (!userRobot) {
            console.warn("Bot not found or not owned by user for start", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found or not owned by user" });
        }

        if ([BotStatus.RUNNING_MOMENTARILY, BotStatus.RUNNING_PERPETUALLY].includes(userRobot.status)) {
            console.warn("Bot is already running", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Bot is already running" });
        }

        // Require at least one API key if none exist
        if (!userRobot.apiKeys || userRobot.apiKeys.length === 0) {
            if (!apiKeys || apiKeys.length === 0 || apiKeys.some((key) => key.platform !== userRobot.template.refId.platform)) {
                console.warn("Invalid API keys for bot start", { userId, botId, route: req.originalUrl });
                await session.abortTransaction();
                return res.status(400).json({ message: `At least one API key for the platform '${userRobot.template.refId.platform}' is required to start the bot` });
            }
            userRobot.apiKeys = apiKeys.map((key) => ({
                platform: key.platform,
                data: key,
            }));
        } else if (apiKeys && apiKeys.length > 0) {
            if (apiKeys.some((key) => key.platform !== userRobot.template.refId.platform)) {
                console.warn("API keys platform mismatch for bot start", { userId, botId, route: req.originalUrl });
                await session.abortTransaction();
                return res.status(400).json({ message: `All API keys must be for the platform '${userRobot.template.refId.platform}'` });
            }
            userRobot.apiKeys = apiKeys.map((key) => ({
                platform: key.platform,
                data: key,
            }));
        }

        const newStatus = startMode === "momentarily" ? BotStatus.RUNNING_MOMENTARILY : BotStatus.RUNNING_PERPETUALLY;

        const pythonConfig = {
            ...userRobot.config,
            apiKeys: userRobot.getDecryptedApiKeys(),
        };

        try {
            const pythonServerResponse = await axios.post(
                process.env.PYTHON_SERVER_URL + "/api/bots/update",
                {
                    botId: userRobot._id.toString(),
                    userId: userId,
                    config: pythonConfig,
                    status: newStatus,
                    templateId: userRobot.template.refId.toString(),
                    platform: userRobot.template.refId.platform,
                    market: userRobot.template.refId.market,
                },
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${process.env.PYTHON_SERVER_API_KEY}`,
                    },
                }
            );

            if (pythonServerResponse.status !== 200) {
                console.error("Failed to start bot on Python server", {
                    userId,
                    botId,
                    route: req.originalUrl,
                    status: pythonServerResponse.status,
                });
                await session.abortTransaction();
                return res.status(pythonServerResponse.status).json({
                    message: pythonServerResponse.data.message || "Failed to start bot on Python server",
                });
            }
        } catch (error) {
            console.error("Failed to communicate with Python server for bot start", {
                userId,
                botId,
                route: req.originalUrl,
                error: error.response ? error.response.data.message : error.message,
            });
            await session.abortTransaction();
            return res.status(500).json({
                message: "Failed to communicate with Python server",
                error: error.response ? error.response.data.message : error.message,
            });
        }

        userRobot.status = newStatus;
        userRobot.lastUpdated = new Date();
        userRobot.runHistory.push({
            action: `Started (${startMode})`,
            timestamp: new Date(),
        });

        await userRobot.save({ session });
        await session.commitTransaction();

        const populatedRobot = await UserRobot.findById(botId)
            .populate({
                path: "template.refId",
                select: "name description image price market risk platform createdBy",
                populate: {
                    path: "createdBy",
                    select: "username profile_image first_name last_name role",
                    match: { is_active: true, role: "admin" },
                },
            });

        const robotResponse = {
            id: populatedRobot.id,
            template: {
                id: populatedRobot.template.refId.id,
                name: populatedRobot.template.refId.name,
                description: populatedRobot.template.refId.description,
                image: populatedRobot.template.refId.image,
                price: populatedRobot.template.refId.price,
                market: populatedRobot.template.refId.market,
                risk: populatedRobot.template.refId.risk,
                platform: populatedRobot.template.refId.platform,
                creator: {
                    id: populatedRobot.template.refId.createdBy.id,
                    username: populatedRobot.template.refId.createdBy.username,
                    profile_image: populatedRobot.template.refId.createdBy.profile_image,
                    display_name: populatedRobot.template.refId.createdBy.first_name && populatedRobot.template.refId.createdBy.last_name
                        ? `${populatedRobot.template.refId.first_name} ${populatedRobot.template.refId.last_name}`
                        : populatedRobot.template.refId.createdBy.username,
                },
            },
            config: populatedRobot.config,
            accountState: populatedRobot.accountState,
            purchased: populatedRobot.purchased,
            transactionId: populatedRobot.transactionId,
            status: populatedRobot.status,
            progress: populatedRobot.progress,
            runHistory: populatedRobot.runHistory,
            apiKeyCount: populatedRobot.apiKeys ? populatedRobot.apiKeys.length : 0,
            lastUpdated: populatedRobot.lastUpdated,
            createdAt: populatedRobot.createdAt,
        };

        console.info("Bot started successfully", { userId, botId, route: req.originalUrl });
        return res.status(200).json({
            message: "Bot started successfully",
            robot: robotResponse,
        });
    } catch (error) {
        console.error("Failed to start bot", { userId: req.user.id, botId: req.params.botId, route: req.originalUrl, error: error.message });
        await session.abortTransaction();
        return res.status(500).json({
            message: "Failed to start bot",
            error: error.message,
        });
    } finally {
        session.endSession();
    }
});

// @desc    Stop a bot
// @route   POST /api/user/bots/:botId/stop
// @access  Private
export const stopUserBot = asyncHandler(async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const userId = req.user.id;
        const { botId } = req.params;
        const { stopMode } = req.body;

        if (!botId || !mongoose.isValidObjectId(botId)) {
            console.warn("Invalid or missing botId for bot stop", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing botId" });
        }
        if (!stopMode || !["pause", "stop"].includes(stopMode)) {
            console.warn("Invalid or missing stopMode for bot stop", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing stopMode" });
        }

        const userRobot = await UserRobot.findOne({ _id: botId, userId })
            .populate("template.refId", "platform market")
            .session(session);
        if (!userRobot) {
            console.warn("Bot not found or not owned by user for stop", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found or not owned by user" });
        }

        if ([BotStatus.STOPPED, BotStatus.PAUSED].includes(userRobot.status)) {
            console.warn("Bot is already stopped or paused", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Bot is already stopped or paused" });
        }

        const newStatus = stopMode === "pause" ? BotStatus.PAUSED : BotStatus.STOPPED;

        try {
            const pythonServerResponse = await axios.post(
                process.env.PYTHON_SERVER_URL + "/api/bots/update",
                {
                    botId: userRobot._id.toString(),
                    userId: userId,
                    config: {
                        ...userRobot.config,
                        apiKeys: userRobot.getDecryptedApiKeys(),
                    },
                    status: newStatus,
                    templateId: userRobot.template.refId.toString(),
                    platform: userRobot.template.refId.platform,
                    market: userRobot.template.refId.market,
                },
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${process.env.PYTHON_SERVER_API_KEY}`,
                    },
                }
            );

            if (pythonServerResponse.status !== 200) {
                console.error("Failed to stop bot on Python server", {
                    userId,
                    botId,
                    route: req.originalUrl,
                    status: pythonServerResponse.status,
                });
                await session.abortTransaction();
                return res.status(pythonServerResponse.status).json({
                    message: pythonServerResponse.data.message || "Failed to stop bot on Python server",
                });
            }
        } catch (error) {
            console.error("Failed to communicate with Python server for bot stop", {
                userId,
                botId,
                route: req.originalUrl,
                error: error.response ? error.response.data.message : error.message,
            });
            await session.abortTransaction();
            return res.status(500).json({
                message: "Failed to communicate with Python server",
                error: error.response ? error.response.data.message : error.message,
            });
        }

        userRobot.status = newStatus;
        userRobot.lastUpdated = new Date();
        userRobot.runHistory.push({
            action: stopMode === "pause" ? "Paused" : "Stopped",
            timestamp: new Date(),
        });

        await userRobot.save({ session });
        await session.commitTransaction();

        const populatedRobot = await UserRobot.findById(botId)
            .populate({
                path: "template.refId",
                select: "name description image price market risk platform createdBy",
                populate: {
                    path: "createdBy",
                    select: "username profile_image first_name last_name role",
                    match: { is_active: true, role: "admin" },
                },
            });

        const robotResponse = {
            id: populatedRobot.id,
            template: {
                id: populatedRobot.template.refId.id,
                name: populatedRobot.template.refId.name,
                description: populatedRobot.template.refId.description,
                image: populatedRobot.template.refId.image,
                price: populatedRobot.template.refId.price,
                market: populatedRobot.template.refId.market,
                risk: populatedRobot.template.refId.risk,
                platform: populatedRobot.template.refId.platform,
                creator: {
                    id: populatedRobot.template.refId.createdBy.id,
                    username: populatedRobot.template.refId.createdBy.username,
                    profile_image: populatedRobot.template.refId.createdBy.profile_image,
                    display_name: populatedRobot.template.refId.createdBy.first_name && populatedRobot.template.refId.createdBy.last_name
                        ? `${populatedRobot.template.refId.first_name} ${populatedRobot.template.refId.last_name}`
                        : populatedRobot.template.refId.createdBy.username,
                },
            },
            config: populatedRobot.config,
            accountState: populatedRobot.accountState,
            purchased: populatedRobot.purchased,
            transactionId: populatedRobot.transactionId,
            status: populatedRobot.status,
            progress: populatedRobot.progress,
            runHistory: populatedRobot.runHistory,
            apiKeyCount: populatedRobot.apiKeys ? populatedRobot.apiKeys.length : 0,
            lastUpdated: populatedRobot.lastUpdated,
            createdAt: populatedRobot.createdAt,
        };

        console.info("Bot stopped successfully", { userId, botId, stopMode, route: req.originalUrl });
        return res.status(200).json({
            message: "Bot stopped successfully",
            robot: robotResponse,
        });
    } catch (error) {
        console.error("Failed to stop bot", { userId: req.user.id, botId: req.params.botId, route: req.originalUrl, error: error.message });
        await session.abortTransaction();
        return res.status(500).json({
            message: "Failed to stop bot",
            error: error.message,
        });
    } finally {
        session.endSession();
    }
});

// @desc    Delete a bot
// @route   DELETE /api/user/bots/:botId
// @access  Private
export const deleteUserBot = asyncHandler(async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const userId = req.user.id;
        const { botId } = req.params;

        if (!botId || !mongoose.isValidObjectId(botId)) {
            console.warn("Invalid or missing botId for bot deletion", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing botId" });
        }

        const userRobot = await UserRobot.findOne({ _id: botId, userId }).session(session);
        if (!userRobot) {
            console.warn("Bot not found or not owned by user for deletion", { userId, botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found or not owned by user" });
        }

        try {
            const pythonServerResponse = await axios.post(
                process.env.PYTHON_SERVER_URL + "/api/bots/delete",
                {
                    botId: botId,
                    userId: userId,
                    templateId: userRobot.template.refId.toString(),
                },
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${process.env.PYTHON_SERVER_API_KEY}`,
                    },
                }
            );

            if (pythonServerResponse.status !== 200) {
                console.error("Failed to delete bot on Python server", {
                    userId,
                    botId,
                    route: req.originalUrl,
                    status: pythonServerResponse.status,
                });
                await session.abortTransaction();
                return res.status(pythonServerResponse.status).json({
                    message: pythonServerResponse.data.message || "Failed to delete bot on Python server",
                });
            }
        } catch (error) {
            console.error("Failed to communicate with Python server for bot deletion", {
                userId,
                botId,
                route: req.originalUrl,
                error: error.response ? error.response.data.message : error.message,
            });
            await session.abortTransaction();
            return res.status(500).json({
                message: "Failed to communicate with Python server for deletion",
                error: error.response ? error.response.data.message : error.message,
            });
        }

        await UserRobot.deleteOne({ _id: botId }).session(session);

        await User.findByIdAndUpdate(
            userId,
            {
                $pull: { robots: { robot_id: new mongoose.Types.ObjectId(botId) } },
                $set: { updated_at: new Date() },
            },
            { session }
        );

        await session.commitTransaction();
        console.info("Bot deleted successfully", { userId, botId, route: req.originalUrl });

        return res.status(200).json({
            message: "Bot deleted successfully",
        });
    } catch (error) {
        console.error("Failed to delete bot", { userId: req.user.id, botId: req.params.botId, route: req.originalUrl, error: error.message });
        await session.abortTransaction();
        return res.status(500).json({
            message: "Failed to delete bot",
            error: error.message,
        });
    } finally {
        session.endSession();
    }
});

// @desc    Update bot progress from Python backend
// @route   POST /api/user/bots/:botId/progress
// @access  Private (Python backend)
export const updateBotProgress = asyncHandler(async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const { botId } = req.params;
        const { progress, notify } = req.body;

        if (!botId || !mongoose.isValidObjectId(botId)) {
            console.warn("Invalid or missing botId for progress update", { botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing botId" });
        }
        if (!progress || typeof progress !== "object" || progress === null) {
            console.warn("Invalid or missing progress data for bot", { botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(400).json({ message: "Invalid or missing progress data" });
        }

        const userRobot = await UserRobot.findById(botId).session(session);
        if (!userRobot) {
            console.warn("Bot not found for progress update", { botId, route: req.originalUrl });
            await session.abortTransaction();
            return res.status(404).json({ message: "Bot not found" });
        }

        userRobot.progress = { ...userRobot.progress, ...progress };
        userRobot.lastUpdated = new Date();
        userRobot.runHistory.push({
            action: "Progress Updated",
            timestamp: new Date(),
            progressSnapshot: progress,
        });
        userRobot.markModified("progress");

        await userRobot.save({ session });
        await session.commitTransaction();

        if (notify) {
            const user = await User.findById(userRobot.userId);
            console.info("Notification triggered for bot progress update", {
                userId: userRobot.userId,
                botId,
                email: user.email,
                route: req.originalUrl,
            });
        }

        console.info("Bot progress updated successfully", { userId: userRobot.userId, botId, route: req.originalUrl });
        return res.status(200).json({
            message: "Bot progress updated successfully",
            progress: userRobot.progress,
        });
    } catch (error) {
        console.error("Failed to update bot progress", { botId: req.params.botId, route: req.originalUrl, error: error.message });
        await session.abortTransaction();
        return res.status(500).json({
            message: "Failed to update bot progress",
            error: error.message,
        });
    } finally {
        session.endSession();
    }
});