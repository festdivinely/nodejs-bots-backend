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

    // Process request body - this can be modified
    if (req.body && typeof req.body === 'object') {
        req.body = cleanValue(req.body);
    }

    // Process query parameters - MODIFIED: Don't reassign req.query directly
    if (req.query && typeof req.query === 'object') {
        // Clean the query object in place instead of reassigning
        const query = req.query;
        Object.keys(query).forEach(key => {
            query[key] = cleanValue(query[key]);
        });
        // No reassignment of req.query - just modify its properties
    }

    // Process URL parameters - MODIFIED: Don't reassign req.params directly
    if (req.params && typeof req.params === 'object') {
        // Clean the params object in place instead of reassigning
        const params = req.params;
        Object.keys(params).forEach(key => {
            params[key] = cleanValue(params[key]);
        });
    }

    next();
};