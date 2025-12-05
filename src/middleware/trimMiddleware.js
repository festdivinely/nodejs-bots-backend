// middleware/trimMiddleware.js
export const trimRequestBody = (req, res, next) => {
    // Helper function to clean a value
    const cleanValue = (value) => {
        // Handle strings
        if (typeof value === 'string') {
            return value.trim();
        }

        // Handle numbers
        if (typeof value === 'number') {
            // Convert to string, trim, and convert back to number
            const stringValue = String(value).trim();
            // Parse back to number (handles floats and integers)
            const trimmedNumber = stringValue.includes('.') ?
                parseFloat(stringValue) :
                parseInt(stringValue, 10);

            // Return original if parsing fails (shouldn't happen with numbers)
            return isNaN(trimmedNumber) ? value : trimmedNumber;
        }

        // Handle booleans, null, undefined - return as-is
        if (typeof value === 'boolean' || value === null || value === undefined) {
            return value;
        }

        // Handle arrays - recursively clean each element
        if (Array.isArray(value)) {
            return value.map(item => cleanValue(item));
        }

        // Handle objects - recursively clean
        if (typeof value === 'object') {
            const cleanedObj = {};
            Object.keys(value).forEach(key => {
                cleanedObj[key] = cleanValue(value[key]);
            });
            return cleanedObj;
        }

        // For any other type (function, symbol, etc.), return as-is
        return value;
    };

    // Process request body
    if (req.body && typeof req.body === 'object') {
        req.body = cleanValue(req.body);
    }

    // Process query parameters
    if (req.query && typeof req.query === 'object') {
        req.query = cleanValue(req.query);
    }

    next();
};