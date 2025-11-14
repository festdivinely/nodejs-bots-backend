// api/_now_launcher.js
import { createRequestListener } from '@vercel/node';

export default createRequestListener({
    // The actual handler file is resolved automatically from the route
    // (e.g. /api/auth/register → api/auth/register.js)
});