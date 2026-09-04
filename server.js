```js
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

// ======================================================
// PORT
// ======================================================

const PORT = process.env.PORT || 3000;

// ======================================================
// DATABASE
// ======================================================

const db = new Database("database.sqlite");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer',
    phone_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    project_type TEXT NOT NULL,
    budget TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS otp_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);
`);

// ======================================================
// SESSIONS
// ======================================================

const sessions = new Map();

function createSession(user) {
    const token = crypto.randomBytes(32).toString("hex");

    sessions.set(token, {
        userId: user.id,
        createdAt: Date.now()
    });

    return token;
}

function getCurrentUser(req) {
    const cookie = req.headers.cookie || "";
    const match = cookie.match(/mta_session=([^;]+)/);

    if (!match) return null;

    const session = sessions.get(match[1]);

    if (!session) return null;

    return db.prepare(`
        SELECT
            id,
            name,
            phone,
            role,
            phone_verified,
            created_at
        FROM users
        WHERE id = ?
    `).get(session.userId);
}

function setSessionCookie(token) {
    return `mta_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`;
}

function clearSessionCookie() {
    return `mta_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`;
}

// ======================================================
// HELPERS
// ======================================================

function sendJSON(res, statusCode, data, extraHeaders = {}) {
    res.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        ...extraHeaders
    });

    res.end(JSON.stringify(data));
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";

        req.on("data", chunk => {
            body += chunk;

            if (body.length > 100000) {
                req.destroy();
                reject(new Error("Request too large"));
            }
        });

        req.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch {
                reject(new Error("Invalid JSON"));
            }
        });

        req.on("error", reject);
    });
}

function validPhone(phone) {
    return /^09\d{9}$/.test(phone);
}

function generateOTP() {
    return String(
        Math.floor(100000 + Math.random() * 900000)
    );
}

function hashOTP(code) {
    return crypto
        .createHash("sha256")
        .update(code)
        .digest("hex");
}

// ======================================================
// OTP
// ======================================================

function createOTP(phone) {
    const code = generateOTP();

    const codeHash = hashOTP(code);

    // 2 دقیقه اعتبار
    const expiresAt = Date.now() + (2 * 60 * 1000);

    // حذف کدهای قبلی
    db.prepare(`
        DELETE FROM otp_codes
        WHERE phone = ?
    `).run(phone);

    db.prepare(`
        INSERT INTO otp_codes
        (phone, code_hash, expires_at)
        VALUES (?, ?, ?)
    `).run(
        phone,
        codeHash,
        expiresAt
    );

    return code;
}

// ======================================================
// SMS
// ======================================================

async function sendSMS(phone, code) {
    /*
        فعلاً SMS واقعی ارسال نمی‌شود.

        وقتی سرویس پیامکی را انتخاب کردیم،
        این قسمت را با API سرویس موردنظر وصل می‌کنیم.
    */

    console.log("");
    console.log("================================");
    console.log("SMS SIMULATION");
    console.log("Phone:", phone);
    console.log("OTP:", code);
    console.log("================================");
    console.log("");

    return true;
}

// ======================================================
// API
// ======================================================

async function handleAPI(req, res) {

    // ==================================================
    // SIGN UP
    // ==================================================

    if (req.method === "POST" && req.url === "/api/signup") {
        try {
            const body = await readBody(req);

            const name = String(body.name || "").trim();
            const phone = String(body.phone || "").trim();
            const password = String(body.password || "");

            if (!name) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "نام را وارد کنید."
                });
            }

            if (!validPhone(phone)) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "شماره موبایل معتبر نیست."
                });
            }

            if (password.length < 6) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "رمز عبور باید حداقل ۶ کاراکتر باشد."
                });
            }

            const existingUser = db.prepare(`
                SELECT id, phone_verified
                FROM users
                WHERE phone = ?
            `).get(phone);

            if (existingUser) {

                if (!existingUser.phone_verified) {
                    const code = createOTP(phone);

                    await sendSMS(phone, code);

                    return sendJSON(res, 200, {
                        success: true,
                        needsVerification: true,
                        message: "این حساب هنوز تأیید نشده است. کد جدید ارسال شد."
                    });
                }

                return sendJSON(res, 409, {
                    success: false,
                    message: "این شماره قبلاً ثبت‌نام کرده است."
                });
            }

            const passwordHash = await bcrypt.hash(password, 12);

            db.prepare(`
                INSERT INTO users
                (name, phone, password_hash)
                VALUES (?, ?, ?)
            `).run(
                name,
                phone,
                passwordHash
            );

            const code = createOTP(phone);

            await sendSMS(phone, code);

            return sendJSON(res, 201, {
                success: true,
                needsVerification: true,
                message: "حساب ساخته شد. کد تأیید ارسال شد."
            });

        } catch (error) {
            console.error(error);

            return sendJSON(res, 500, {
                success: false,
                message: "خطایی در ثبت‌نام رخ داد."
            });
        }
    }

    // ==================================================
    // VERIFY PHONE
    // ==================================================

    if (
        req.method === "POST" &&
        req.url === "/api/verify-phone"
    ) {
        try {
            const body = await readBody(req);

            const phone = String(body.phone || "").trim();
            const code = String(body.code || "").trim();

            if (!validPhone(phone)) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "شماره موبایل معتبر نیست."
                });
            }

            if (!/^\d{6}$/.test(code)) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "کد تأیید باید ۶ رقمی باشد."
                });
            }

            const otp = db.prepare(`
                SELECT *
                FROM otp_codes
                WHERE phone = ?
                ORDER BY id DESC
                LIMIT 1
            `).get(phone);

            if (!otp) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "کد تأیید پیدا نشد. دوباره درخواست کد کنید."
                });
            }

            if (Date.now() > otp.expires_at) {
                db.prepare(`
                    DELETE FROM otp_codes
                    WHERE id = ?
                `).run(otp.id);

                return sendJSON(res, 400, {
                    success: false,
                    message: "کد منقضی شده است."
                });
            }

            if (otp.attempts >= 5) {
                db.prepare(`
                    DELETE FROM otp_codes
                    WHERE id = ?
                `).run(otp.id);

                return sendJSON(res, 429, {
                    success: false,
                    message: "تعداد تلاش بیش از حد مجاز است. کد جدید بگیرید."
                });
            }

            const inputHash = hashOTP(code);

            if (inputHash !== otp.code_hash) {
                db.prepare(`
                    UPDATE otp_codes
                    SET attempts = attempts + 1
                    WHERE id = ?
                `).run(otp.id);

                return sendJSON(res, 400, {
                    success: false,
                    message: "کد تأیید اشتباه است."
                });
            }

            const user = db.prepare(`
                SELECT *
                FROM users
                WHERE phone = ?
            `).get(phone);

            if (!user) {
                return sendJSON(res, 404, {
                    success: false,
                    message: "کاربر پیدا نشد."
                });
            }

            db.prepare(`
                UPDATE users
                SET phone_verified = 1
                WHERE id = ?
            `).run(user.id);

            db.prepare(`
                DELETE FROM otp_codes
                WHERE phone = ?
            `).run(phone);

            const updatedUser = db.prepare(`
                SELECT
                    id,
                    name,
                    phone,
                    role,
                    phone_verified,
                    created_at
                FROM users
                WHERE id = ?
            `).get(user.id);

            const token = createSession(updatedUser);

            return sendJSON(
                res,
                200,
                {
                    success: true,
                    message: "شماره موبایل با موفقیت تأیید شد.",
                    user: updatedUser
                },
                {
                    "Set-Cookie": setSessionCookie(token)
                }
            );

        } catch (error) {
            console.error(error);

            return sendJSON(res, 500, {
                success: false,
                message: "خطایی هنگام تأیید شماره رخ داد."
            });
        }
    }

    // ==================================================
    // RESEND OTP
    // ==================================================

    if (
        req.method === "POST" &&
        req.url === "/api/resend-otp"
    ) {
        try {
            const body = await readBody(req);

            const phone = String(body.phone || "").trim();

            if (!validPhone(phone)) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "شماره موبایل معتبر نیست."
                });
            }

            const user = db.prepare(`
                SELECT id
                FROM users
                WHERE phone = ?
            `).get(phone);

            if (!user) {
                return sendJSON(res, 404, {
                    success: false,
                    message: "کاربری با این شماره وجود ندارد."
                });
            }

            const code = createOTP(phone);

            await sendSMS(phone, code);

            return sendJSON(res, 200, {
                success: true,
                message: "کد جدید ارسال شد."
            });

        } catch (error) {
            console.error(error);

            return sendJSON(res, 500, {
                success: false,
                message: "خطایی هنگام ارسال کد رخ داد."
            });
        }
    }

    // ==================================================
    // LOGIN
    // ==================================================

    if (req.method === "POST" && req.url === "/api/login") {
        try {
            const body = await readBody(req);

            const phone = String(body.phone || "").trim();
            const password = String(body.password || "");

            if (!validPhone(phone)) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "شماره موبایل معتبر نیست."
                });
            }

            const user = db.prepare(`
                SELECT *
                FROM users
                WHERE phone = ?
            `).get(phone);

            if (!user) {
                return sendJSON(res, 401, {
                    success: false,
                    message: "شماره موبایل یا رمز عبور اشتباه است."
                });
            }

            const passwordCorrect = await bcrypt.compare(
                password,
                user.password_hash
            );

            if (!passwordCorrect) {
                return sendJSON(res, 401, {
                    success: false,
                    message: "شماره موبایل یا رمز عبور اشتباه است."
                });
            }

            // شماره باید تأیید شده باشد
            if (!user.phone_verified) {
                const code = createOTP(phone);

                await sendSMS(phone, code);

                return sendJSON(res, 403, {
                    success: false,
                    needsVerification: true,
                    message: "شماره موبایل شما تأیید نشده است. کد جدید ارسال شد."
                });
            }

            const token = createSession(user);

            return sendJSON(
                res,
                200,
                {
                    success: true,
                    message: "ورود موفق بود.",
                    user: {
                        id: user.id,
                        name: user.name,
                        phone: user.phone,
                        role: user.role,
                        phone_verified: user.phone_verified
                    }
                },
                {
                    "Set-Cookie": setSessionCookie(token)
                }
            );

        } catch (error) {
            console.error(error);

            return sendJSON(res, 500, {
                success: false,
                message: "خطایی هنگام ورود رخ داد."
            });
        }
    }

    // ==================================================
    // CURRENT USER
    // ==================================================

    if (req.method === "GET" && req.url === "/api/me") {

        const user = getCurrentUser(req);

        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: "وارد حساب نشده‌اید."
            });
        }

        return sendJSON(res, 200, {
            success: true,
            user
        });
    }

    // ==================================================
    // LOGOUT
    // ==================================================

    if (req.method === "POST" && req.url === "/api/logout") {

        const cookie = req.headers.cookie || "";
        const match = cookie.match(/mta_session=([^;]+)/);

        if (match) {
            sessions.delete(match[1]);
        }

        return sendJSON(
            res,
            200,
            {
                success: true,
                message: "با موفقیت خارج شدید."
            },
            {
                "Set-Cookie": clearSessionCookie()
            }
        );
    }

    // ==================================================
    // CREATE PROJECT
    // ==================================================

    if (
        req.method === "POST" &&
        req.url === "/api/projects"
    ) {
        try {
            const user = getCurrentUser(req);

            // کاربر حتماً باید وارد شده باشد
            if (!user) {
                return sendJSON(res, 401, {
                    success: false,
                    message: "برای ثبت پروژه ابتدا وارد حساب خود شوید."
                });
            }

            // شماره موبایل هم باید تأیید شده باشد
            if (!user.phone_verified) {
                return sendJSON(res, 403, {
                    success: false,
                    message: "ابتدا شماره موبایل خود را تأیید کنید."
                });
            }

            const body = await readBody(req);

            const firstName = String(
                body.firstName || ""
            ).trim();

            const lastName = String(
                body.lastName || ""
            ).trim();

            const phone = String(
                body.phone || user.phone
            ).trim();

            const projectType = String(
                body.projectType || ""
            ).trim();

            const budget = String(
                body.budget || ""
            ).trim();

            const description = String(
                body.description || ""
            ).trim();

            if (!firstName || !lastName) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "نام و نام خانوادگی را وارد کنید."
                });
            }

            if (!validPhone(phone)) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "شماره موبایل معتبر نیست."
                });
            }

            if (!projectType) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "نوع پروژه را انتخاب کنید."
                });
            }

            if (!budget) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "بودجه پروژه را انتخاب کنید."
                });
            }

            if (description.length < 10) {
                return sendJSON(res, 400, {
                    success: false,
                    message: "توضیحات پروژه باید حداقل ۱۰ کاراکتر باشد."
                });
            }

            const result = db.prepare(`
                INSERT INTO projects
                (
                    user_id,
                    first_name,
                    last_name,
                    phone,
                    project_type,
                    budget,
                    description
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(
                user.id,
                firstName,
                lastName,
                phone,
                projectType,
                budget,
                description
            );

            return sendJSON(res, 201, {
                success: true,
                message: "درخواست پروژه با موفقیت ثبت شد.",
                projectId: result.lastInsertRowid
            });

        } catch (error) {
            console.error(error);

            return sendJSON(res, 500, {
                success: false,
                message: "خطایی هنگام ثبت پروژه رخ داد."
            });
        }
    }

    // ==================================================
    // USER PROJECTS
    // ==================================================

    if (
        req.method === "GET" &&
        req.url === "/api/projects"
    ) {

        const user = getCurrentUser(req);

        if (!user) {
            return sendJSON(res, 401, {
                success: false,
                message: "ابتدا وارد حساب شوید."
            });
        }

        const projects = db.prepare(`
            SELECT
                id,
                first_name,
                last_name,
                phone,
                project_type,
                budget,
                description,
                status,
                created_at
            FROM projects
            WHERE user_id = ?
            ORDER BY id DESC
        `).all(user.id);

        return sendJSON(res, 200, {
            success: true,
            projects
        });
    }

    return sendJSON(res, 404, {
        success: false,
        message: "API not found"
    });
}

// ======================================================
// STATIC FILE SERVER
// ======================================================

const server = http.createServer(async (req, res) => {

    try {

        // ==================================================
        // CORS
        // ==================================================

        res.setHeader(
            "Access-Control-Allow-Origin",
            "*"
        );

        res.setHeader(
            "Access-Control-Allow-Methods",
            "GET, POST, OPTIONS"
        );

        res.setHeader(
            "Access-Control-Allow-Headers",
            "Content-Type"
        );

        // ==================================================
        // PREFLIGHT
        // ==================================================

        if (req.method === "OPTIONS") {
            res.writeHead(204);
            return res.end();
        }

        // ==================================================
        // API
        // ==================================================

        if (req.url.startsWith("/api/")) {
            return await handleAPI(req, res);
        }

        // ==================================================
        // HOME
        // ==================================================

        if (
            req.url === "/" ||
            req.url === "/index.html"
        ) {

            const indexPath = path.join(
                __dirname,
                "index.html"
            );

            if (fs.existsSync(indexPath)) {

                res.writeHead(200, {
                    "Content-Type":
                        "text/html; charset=utf-8"
                });

                return fs
                    .createReadStream(indexPath)
                    .pipe(res);
            }

            res.writeHead(200, {
                "Content-Type":
                    "text/html; charset=utf-8"
            });

            return res.end(`
                <h1>MTA Studio</h1>
                <p>Backend is running.</p>
            `);
        }

        // ==================================================
        // STATIC FILES
        // ==================================================

        const requestedPath = decodeURIComponent(
            req.url.split("?")[0]
        );

        const filePath = path.join(
            __dirname,
            requestedPath
        );

        if (
            filePath.startsWith(__dirname) &&
            fs.existsSync(filePath) &&
            fs.statSync(filePath).isFile()
        ) {

            const ext = path.extname(filePath).toLowerCase();

            const contentTypes = {
                ".html": "text/html; charset=utf-8",
                ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".json": "application/json; charset=utf-8",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".svg": "image/svg+xml",
                ".ico": "image/x-icon",
                ".webp": "image/webp"
            };

            res.writeHead(200, {
                "Content-Type":
                    contentTypes[ext] ||
                    "application/octet-stream"
            });

            return fs
                .createReadStream(filePath)
                .pipe(res);
        }

        // ==================================================
        // NOT FOUND
        // ==================================================

        res.writeHead(404);
        res.end("Not Found");

    } catch (error) {

        console.error(error);

        res.writeHead(500);
        res.end("Internal Server Error");
    }
});

// ======================================================
// START SERVER
// ======================================================

server.listen(PORT, "0.0.0.0", () => {

    console.log("");
    console.log("================================");
    console.log("       MTA STUDIO BACKEND");
    console.log("================================");
    console.log(`Server running on port ${PORT}`);
    console.log("Database: connected");
    console.log("Authentication: ready");
    console.log("OTP system: ready");
    console.log("Projects API: ready");
    console.log("================================");
    console.log("");

});
```
