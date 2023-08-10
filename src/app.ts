import express, { Request, Response } from "express";
import crypto from "crypto";
import fs from "fs/promises"; // Import the promise-based version of fs
import path from "path";
import dotenv from "dotenv";

interface RequestWithSignature extends Request {
  signature?: string;
}

dotenv.config();

// Check required environment variables
const { WEBHOOK_ENDPOINT, APP_SECRET, TOKEN, DATA_DIRECTORY, PORT } =
  process.env;
if (!WEBHOOK_ENDPOINT || !APP_SECRET || !TOKEN || !DATA_DIRECTORY || !PORT) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

const app = express();

app.use(
  express.json({
    verify: (
      req: RequestWithSignature,
      _res: Response,
      buf: Buffer,
      _encoding: string
    ) => {
      const sha1Signature = crypto
        .createHmac("sha1", APP_SECRET)
        .update(buf)
        .digest("hex");
      req.signature = `sha1=${sha1Signature}`;
    },
  })
);

app.get("/", (_req: Request, res: Response) => {
  res.send("OK");
});

app.get(WEBHOOK_ENDPOINT, (req: Request, res: Response) => {
  if (
    req.query["hub.mode"] === "subscribe" &&
    req.query["hub.verify_token"] === TOKEN
  ) {
    res.send(req.query["hub.challenge"] as string);
  } else {
    res.sendStatus(400);
  }
});

app.post(WEBHOOK_ENDPOINT, async (req: RequestWithSignature, res: Response) => {
  if (req.headers["x-hub-signature"] !== req.signature) {
    res.sendStatus(401);
    return;
  }

  const formattedDate = formatDate(new Date());
  const filename = `${formattedDate}.json`;
  const filePath = path.join(DATA_DIRECTORY, filename);

  try {
    await fs.writeFile(filePath, JSON.stringify(req.body, null, 2));
    res.sendStatus(200);
  } catch (error) {
    console.error("Error writing file:", error);
    res.sendStatus(500);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

function formatDate(date: Date): string {
  return `${date.getFullYear()}${String(date.getMonth() + 1).padStart(
    2,
    "0"
  )}${String(date.getDate()).padStart(2, "0")}${String(
    date.getHours()
  ).padStart(2, "0")}${String(date.getMinutes()).padStart(2, "0")}${String(
    date.getSeconds()
  ).padStart(2, "0")}${String(date.getMilliseconds()).padStart(3, "0")}`;
}
