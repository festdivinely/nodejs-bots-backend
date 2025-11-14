// middleware/applyMiddleware.js
export const applyMiddleware = (middleware) => (req, res) =>
    new Promise((resolve, reject) => {
        middleware(req, res, (result) => {
            if (result instanceof Error) return reject(result);
            resolve(result);
        });
    });