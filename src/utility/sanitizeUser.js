// utils/sanitizeUser.js
export const sanitizeRobot = (robot) => {
    return {
        robotId: robot.robotId,
        robotName: robot.robotName,
        botType: robot.botType,
        description: robot.description,
        image: bot.image,
        efficiency: bot.efficiency,
        isFree: robot.isFree,
        price: robot.price,
        purchased: robot.purchased,
        status: robot.status,
        startBot: robot.startBot,
        stopBot: robot.stopBot,
        lastUpdated: robot.lastUpdated,
        runHistory: robot.runHistory, // safe, unless you store sensitive info in it
    };
};

export const sanitizeUser = (user) => {
    if (!user) return null;

    return {
        id: user._id,
        username: user.username,
        email: user.email,
        profileImage: user.profileImage,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName,
        middleName: user.middleName,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        phoneNumber: user.phoneNumber,
        addressLine1: user.addressLine1,
        addressLine2: user.addressLine2,
        city: user.city,
        state: user.state,
        zipcode: user.zipcode,
        country: user.country,
        preferredLanguage: user.preferredLanguage,
        notificationPreferences: user.notificationPreferences,
        kycStatus: user.kycStatus,
        riskProfile: user.riskProfile,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,

        // ✅ Include sanitized robots
        robots: user.robots ? user.robots.map(sanitizeRobot) : [],
    };
};
