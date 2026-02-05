import { UAParser } from "ua-parser-js";

export const getDeviceInfo = (req) => {
  const userAgent = req.headers["user-agent"];

  const parser = new UAParser(userAgent);

  const result = parser.getResult();
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  return {
    ip,
    userAgent,
    os: `${result.os.name || "unknown"} ${result.os.version || ""}`.trim(),
    browser:
      `${result.browser.name || "unknown"} ${result.browser.version || ""}`.trim(),
    device: result.device.model
      ? `${result.device.vendor || "Unknown"} ${result.device.model}`
      : "Desktop/Laptop",
  };
};
