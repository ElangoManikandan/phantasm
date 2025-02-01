import { readFileSync } from "fs";
import { join } from "path";

export default function handler(req, res) {
  const filePath = join(process.cwd(), "public", "index.html");
  const fileContents = readFileSync(filePath, "utf8");

  res.setHeader("Content-Type", "text/html");
  res.status(200).send(fileContents);
}
