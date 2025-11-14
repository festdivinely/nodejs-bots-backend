export default function handler(req, res) {
    res.send(`
    <html><head><title>Trade Divinely Bot API</title></head>
    <body style="font-family:Arial;background:#000;color:#0f0;text-align:center;padding:2rem;">
      <h1>TRADE DIVINELY BOT API</h1>
      <p>Serverless backend is <strong>ALIVE</strong>.</p>
      <p><strong>${new Date().toISOString()}</strong></p>
    </body></html>
  `);
}