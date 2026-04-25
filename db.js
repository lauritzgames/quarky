const crypto = require('crypto');
const mysql = require('mysql2/promise');

const algorithm = 'aes-256-gcm';
const sessionTtlHours = Number(process.env.SESSION_TTL_HOURS || 24 * 7);

let pool;

function getPool() {
    if (pool) {
        return pool;
    }

    const {
        MYSQL_HOST,
        MYSQL_PORT = '3306',
        MYSQL_USER,
        MYSQL_PASSWORD,
        MYSQL_DATABASE
    } = process.env;

    if (!MYSQL_HOST || !MYSQL_USER || !MYSQL_DATABASE) {
        throw new Error('Missing MySQL configuration. Set MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, and MYSQL_DATABASE.');
    }

    pool = mysql.createPool({
        host: MYSQL_HOST,
        port: Number(MYSQL_PORT),
        user: MYSQL_USER,
        password: MYSQL_PASSWORD || '',
        database: MYSQL_DATABASE,
        waitForConnections: true,
        connectionLimit: 10
    });

    return pool;
}

function getEncryptionKey() {
    const key = process.env.APP_ENCRYPTION_KEY;
    if (!key) {
        throw new Error('Missing APP_ENCRYPTION_KEY. Use a 64 character hex string.');
    }

    const buffer = Buffer.from(key, 'hex');
    if (buffer.length !== 32) {
        throw new Error('APP_ENCRYPTION_KEY must decode to 32 bytes. Use 64 hex characters.');
    }

    return buffer;
}

function encryptText(value) {
    if (value == null || value === '') {
        return null;
    }

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(algorithm, getEncryptionKey(), iv);
    const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptText(value) {
    if (!value) {
        return '';
    }

    const [ivHex, tagHex, encryptedHex] = String(value).split(':');
    if (!ivHex || !tagHex || !encryptedHex) {
        return '';
    }

    const decipher = crypto.createDecipheriv(
        algorithm,
        getEncryptionKey(),
        Buffer.from(ivHex, 'hex')
    );
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedHex, 'hex')),
        decipher.final()
    ]);
    return decrypted.toString('utf8');
}

function encryptJson(value) {
    return encryptText(JSON.stringify(value ?? []));
}

function decryptJson(value) {
    if (!value) {
        return [];
    }

    try {
        const parsed = JSON.parse(decryptText(value));
        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        return [];
    }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const derived = crypto.scryptSync(password, salt, 64);
    return `${salt}:${derived.toString('hex')}`;
}

function verifyPassword(password, storedValue) {
    const [salt, storedHash] = String(storedValue || '').split(':');
    if (!salt || !storedHash) {
        return false;
    }

    const incomingHash = crypto.scryptSync(password, salt, 64);
    const originalHash = Buffer.from(storedHash, 'hex');
    if (originalHash.length !== incomingHash.length) {
        return false;
    }

    return crypto.timingSafeEqual(originalHash, incomingHash);
}

function sha256(value) {
    return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function buildFileUrl(storedName, name = 'download.bin') {
    return `/files/${encodeURIComponent(storedName)}?name=${encodeURIComponent(name)}`;
}

function buildMediaUrl(storedName) {
    return `/media/${encodeURIComponent(storedName)}`;
}

function normalizeVisibility(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'private' || normalized === 'unlisted') {
        return normalized;
    }

    return 'public';
}

function normalizeTag(value) {
    return String(value || '')
        .trim()
        .toLowerCase()
        .replace(/[^\w-]+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 32);
}

function normalizeTags(value) {
    const entries = Array.isArray(value)
        ? value
        : String(value || '')
            .split(',')
            .map((entry) => entry.trim());

    return [...new Set(entries.map(normalizeTag).filter(Boolean))].slice(0, 12);
}

function normalizeChangelogEntry(entry) {
    if (typeof entry === 'string') {
        const content = entry.trim();
        if (!content) {
            return null;
        }

        return {
            id: crypto.randomUUID(),
            title: content,
            body: '',
            createdAt: new Date().toISOString()
        };
    }

    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const title = String(entry.title || '').trim();
    const body = String(entry.body || '').trim();
    if (!title && !body) {
        return null;
    }

    return {
        id: String(entry.id || crypto.randomUUID()),
        title: title || 'Update',
        body,
        createdAt: entry.createdAt || new Date().toISOString()
    };
}

function normalizeChangelog(value) {
    if (Array.isArray(value)) {
        return value.map(normalizeChangelogEntry).filter(Boolean).slice(0, 50);
    }

    if (typeof value === 'string') {
        return value
            .split('\n')
            .map((line) => line.trim())
            .filter(Boolean)
            .map((line) => {
                const [titlePart, ...bodyParts] = line.split('|');
                return normalizeChangelogEntry({
                    title: titlePart.trim(),
                    body: bodyParts.join('|').trim()
                });
            })
            .filter(Boolean)
            .slice(0, 50);
    }

    return [];
}

function normalizeDevlogs(value) {
    return normalizeChangelog(value).slice(0, 40);
}

function normalizeKnownBugEntry(entry) {
    if (typeof entry === 'string') {
        const content = entry.trim();
        if (!content) {
            return null;
        }

        return {
            id: crypto.randomUUID(),
            title: content,
            body: '',
            status: 'open',
            createdAt: new Date().toISOString()
        };
    }

    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const title = String(entry.title || '').trim();
    const body = String(entry.body || '').trim();
    const status = String(entry.status || '').trim().toLowerCase();
    if (!title && !body) {
        return null;
    }

    return {
        id: String(entry.id || crypto.randomUUID()),
        title: title || 'Known issue',
        body,
        status: ['open', 'in-progress', 'fixed'].includes(status) ? status : 'open',
        createdAt: entry.createdAt || new Date().toISOString()
    };
}

function normalizeKnownBugs(value) {
    if (Array.isArray(value)) {
        return value.map(normalizeKnownBugEntry).filter(Boolean).slice(0, 30);
    }

    if (typeof value === 'string') {
        return value
            .split('\n')
            .map((line) => line.trim())
            .filter(Boolean)
            .map((line) => {
                const [titlePart, ...bodyParts] = line.split('|');
                return normalizeKnownBugEntry({
                    title: titlePart.trim(),
                    body: bodyParts.join('|').trim()
                });
            })
            .filter(Boolean)
            .slice(0, 30);
    }

    return [];
}

function normalizeExternalLinkEntry(entry) {
    if (typeof entry === 'string') {
        const line = entry.trim();
        if (!line) {
            return null;
        }

        const [labelPart, ...urlParts] = line.split('|');
        const parsedUrl = urlParts.length ? urlParts.join('|').trim() : labelPart.trim();
        const parsedLabel = urlParts.length ? labelPart.trim() : '';
        return normalizeExternalLinkEntry({
            label: parsedLabel,
            url: parsedUrl
        });
    }

    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const rawUrl = String(entry.url || '').trim();
    if (!rawUrl) {
        return null;
    }

    let url;
    try {
        url = new URL(rawUrl);
    } catch (error) {
        return null;
    }

    if (!['http:', 'https:'].includes(url.protocol)) {
        return null;
    }

    const label = String(entry.label || url.hostname).trim().slice(0, 80);

    return {
        id: String(entry.id || crypto.randomUUID()),
        label: label || url.hostname,
        url: url.toString(),
        hostname: url.hostname
    };
}

function normalizeExternalLinks(value) {
    if (Array.isArray(value)) {
        return value.map(normalizeExternalLinkEntry).filter(Boolean).slice(0, 12);
    }

    if (typeof value === 'string') {
        return value
            .split('\n')
            .map((line) => line.trim())
            .filter(Boolean)
            .map((line) => normalizeExternalLinkEntry(line))
            .filter(Boolean)
            .slice(0, 12);
    }

    return [];
}

function normalizeWordList(value) {
    const items = Array.isArray(value)
        ? value
        : String(value || '')
            .split(/[\n,]/)
            .map((entry) => entry.trim().toLowerCase());

    return [...new Set(items.map((entry) => entry.replace(/\s+/g, ' ').trim()).filter(Boolean))].slice(0, 200);
}

function normalizeFileEntry(entry, kind = 'attachment') {
    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const storedName = String(entry.storedName || '').trim();
    if (!storedName) {
        return null;
    }

    const name = String(entry.name || entry.originalName || storedName).trim();
    const mimeType = String(entry.mimeType || 'application/octet-stream').trim() || 'application/octet-stream';
    const size = Math.max(0, Number(entry.size) || 0);

    return {
        storedName,
        name,
        mimeType,
        size,
        kind,
        url: kind === 'attachment' ? buildFileUrl(storedName, name) : buildMediaUrl(storedName)
    };
}

function normalizeFileEntries(value, kind = 'attachment') {
    if (!Array.isArray(value)) {
        return [];
    }

    return value
        .map((entry) => normalizeFileEntry(entry, kind))
        .filter(Boolean)
        .slice(0, kind === 'screenshot' ? 24 : 50);
}

function normalizeProfileMedia(value, kind) {
    if (!value) {
        return null;
    }

    if (typeof value === 'string') {
        try {
            return normalizeProfileMedia(JSON.parse(value), kind);
        } catch (error) {
            return null;
        }
    }

    return normalizeFileEntry(value, kind);
}

function normalizeAnnouncementLink(value) {
    const link = String(value || '').trim();
    return link.slice(0, 255);
}

function normalizeEmailAddress(value) {
    return String(value || '').trim().toLowerCase();
}

function normalizeSiteSettingsInput(currentSettings = {}, updates = {}) {
    return {
        registrationsEnabled: Object.prototype.hasOwnProperty.call(updates, 'registrationsEnabled')
            ? Boolean(updates.registrationsEnabled)
            : Boolean(currentSettings.registrationsEnabled),
        loginEnabled: Object.prototype.hasOwnProperty.call(updates, 'loginEnabled')
            ? Boolean(updates.loginEnabled)
            : Boolean(currentSettings.loginEnabled),
        uploadsEnabled: Object.prototype.hasOwnProperty.call(updates, 'uploadsEnabled')
            ? Boolean(updates.uploadsEnabled)
            : Boolean(currentSettings.uploadsEnabled),
        projectLimitEnabled: Object.prototype.hasOwnProperty.call(updates, 'projectLimitEnabled')
            ? Boolean(updates.projectLimitEnabled)
            : Boolean(currentSettings.projectLimitEnabled),
        maxProjectsPerUser: Math.max(1, Number(updates.maxProjectsPerUser ?? currentSettings.maxProjectsPerUser) || 10),
        uploadSizeLimitEnabled: Object.prototype.hasOwnProperty.call(updates, 'uploadSizeLimitEnabled')
            ? Boolean(updates.uploadSizeLimitEnabled)
            : Boolean(currentSettings.uploadSizeLimitEnabled),
        maxUploadSizeMb: Math.max(1, Number(updates.maxUploadSizeMb ?? currentSettings.maxUploadSizeMb) || 25),
        inviteOnlyEnabled: Object.prototype.hasOwnProperty.call(updates, 'inviteOnlyEnabled')
            ? Boolean(updates.inviteOnlyEnabled)
            : Boolean(currentSettings.inviteOnlyEnabled),
        approvalRequired: Object.prototype.hasOwnProperty.call(updates, 'approvalRequired')
            ? Boolean(updates.approvalRequired)
            : Boolean(currentSettings.approvalRequired),
        newAccountRestrictionsEnabled: Object.prototype.hasOwnProperty.call(updates, 'newAccountRestrictionsEnabled')
            ? Boolean(updates.newAccountRestrictionsEnabled)
            : Boolean(currentSettings.newAccountRestrictionsEnabled),
        newAccountRestrictionHours: Math.max(1, Number(updates.newAccountRestrictionHours ?? currentSettings.newAccountRestrictionHours) || 24),
        announcementEnabled: Object.prototype.hasOwnProperty.call(updates, 'announcementEnabled')
            ? Boolean(updates.announcementEnabled)
            : Boolean(currentSettings.announcementEnabled),
        announcementText: Object.prototype.hasOwnProperty.call(updates, 'announcementText')
            ? String(updates.announcementText || '').trim().slice(0, 500)
            : String(currentSettings.announcementText || ''),
        announcementLink: Object.prototype.hasOwnProperty.call(updates, 'announcementLink')
            ? normalizeAnnouncementLink(updates.announcementLink)
            : normalizeAnnouncementLink(currentSettings.announcementLink),
        trustLevelEnabled: Object.prototype.hasOwnProperty.call(updates, 'trustLevelEnabled')
            ? Boolean(updates.trustLevelEnabled)
            : Boolean(currentSettings.trustLevelEnabled),
        lowTrustAgeHours: Math.max(1, Number(updates.lowTrustAgeHours ?? currentSettings.lowTrustAgeHours) || 72),
        lowTrustCommentCooldownSeconds: Math.max(0, Number(updates.lowTrustCommentCooldownSeconds ?? currentSettings.lowTrustCommentCooldownSeconds) || 45),
        lowTrustProjectCooldownMinutes: Math.max(0, Number(updates.lowTrustProjectCooldownMinutes ?? currentSettings.lowTrustProjectCooldownMinutes) || 30),
        wordBlacklist: Object.prototype.hasOwnProperty.call(updates, 'wordBlacklist')
            ? normalizeWordList(updates.wordBlacklist)
            : normalizeWordList(currentSettings.wordBlacklist)
    };
}

function getBootstrapAdminConfig() {
    const username = String(process.env.BOOTSTRAP_ADMIN_USERNAME || '').trim();
    const email = String(process.env.BOOTSTRAP_ADMIN_EMAIL || '').trim();
    const password = String(process.env.BOOTSTRAP_ADMIN_PASSWORD || '');
    const anyValue = Boolean(username || email || password);

    if (!anyValue) {
        return null;
    }

    if (!username || !email || !password) {
        throw new Error('Set BOOTSTRAP_ADMIN_USERNAME, BOOTSTRAP_ADMIN_EMAIL, and BOOTSTRAP_ADMIN_PASSWORD together.');
    }

    if (password.length < 12) {
        throw new Error('BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters long.');
    }

    return { username, email, password };
}

async function columnExists(database, tableName, columnName) {
    const [rows] = await database.query(
        `
            SELECT COUNT(*) AS count
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = ?
              AND column_name = ?
        `,
        [tableName, columnName]
    );

    return rows[0].count > 0;
}

async function addColumnIfMissing(database, tableName, columnName, sql) {
    if (!(await columnExists(database, tableName, columnName))) {
        await database.query(sql);
    }
}

async function ensureUsersTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id CHAR(36) NOT NULL UNIQUE,
            username VARCHAR(64) NOT NULL UNIQUE,
            email_encrypted TEXT NOT NULL,
            email_hash CHAR(64) NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(16) NOT NULL DEFAULT 'user',
            email_verified TINYINT(1) NOT NULL DEFAULT 1,
            email_verified_at DATETIME NULL,
            is_approved TINYINT(1) NOT NULL DEFAULT 1,
            approved_at DATETIME NULL,
            is_banned TINYINT(1) NOT NULL DEFAULT 0,
            banned_at DATETIME NULL,
            ban_reason_encrypted LONGTEXT NULL,
            ban_expires_at DATETIME NULL,
            two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0,
            two_factor_secret_encrypted TEXT NULL,
            two_factor_backup_codes_encrypted LONGTEXT NULL,
            two_factor_confirmed_at DATETIME NULL,
            force_password_reset TINYINT(1) NOT NULL DEFAULT 0,
            bio_encrypted LONGTEXT NULL,
            avatar_media_encrypted LONGTEXT NULL,
            banner_media_encrypted LONGTEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await addColumnIfMissing(database, 'users', 'user_id', 'ALTER TABLE users ADD COLUMN user_id CHAR(36) NULL AFTER id');
    await addColumnIfMissing(database, 'users', 'email_hash', 'ALTER TABLE users ADD COLUMN email_hash CHAR(64) NULL AFTER email_encrypted');
    await addColumnIfMissing(database, 'users', 'role', "ALTER TABLE users ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'user' AFTER password_hash");
    await addColumnIfMissing(database, 'users', 'email_verified', "ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 1 AFTER role");
    await addColumnIfMissing(database, 'users', 'email_verified_at', 'ALTER TABLE users ADD COLUMN email_verified_at DATETIME NULL AFTER email_verified');
    await addColumnIfMissing(database, 'users', 'is_approved', "ALTER TABLE users ADD COLUMN is_approved TINYINT(1) NOT NULL DEFAULT 1 AFTER email_verified_at");
    await addColumnIfMissing(database, 'users', 'approved_at', 'ALTER TABLE users ADD COLUMN approved_at DATETIME NULL AFTER is_approved');
    await addColumnIfMissing(database, 'users', 'is_banned', 'ALTER TABLE users ADD COLUMN is_banned TINYINT(1) NOT NULL DEFAULT 0 AFTER role');
    await addColumnIfMissing(database, 'users', 'banned_at', 'ALTER TABLE users ADD COLUMN banned_at DATETIME NULL AFTER is_banned');
    await addColumnIfMissing(database, 'users', 'ban_reason_encrypted', 'ALTER TABLE users ADD COLUMN ban_reason_encrypted LONGTEXT NULL AFTER banned_at');
    await addColumnIfMissing(database, 'users', 'ban_expires_at', 'ALTER TABLE users ADD COLUMN ban_expires_at DATETIME NULL AFTER ban_reason_encrypted');
    await addColumnIfMissing(database, 'users', 'two_factor_enabled', 'ALTER TABLE users ADD COLUMN two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER ban_expires_at');
    await addColumnIfMissing(database, 'users', 'two_factor_secret_encrypted', 'ALTER TABLE users ADD COLUMN two_factor_secret_encrypted TEXT NULL AFTER two_factor_enabled');
    await addColumnIfMissing(database, 'users', 'two_factor_backup_codes_encrypted', 'ALTER TABLE users ADD COLUMN two_factor_backup_codes_encrypted LONGTEXT NULL AFTER two_factor_secret_encrypted');
    await addColumnIfMissing(database, 'users', 'two_factor_confirmed_at', 'ALTER TABLE users ADD COLUMN two_factor_confirmed_at DATETIME NULL AFTER two_factor_backup_codes_encrypted');
    await addColumnIfMissing(database, 'users', 'force_password_reset', 'ALTER TABLE users ADD COLUMN force_password_reset TINYINT(1) NOT NULL DEFAULT 0 AFTER two_factor_confirmed_at');
    await addColumnIfMissing(database, 'users', 'bio_encrypted', 'ALTER TABLE users ADD COLUMN bio_encrypted LONGTEXT NULL AFTER force_password_reset');
    await addColumnIfMissing(database, 'users', 'avatar_media_encrypted', 'ALTER TABLE users ADD COLUMN avatar_media_encrypted LONGTEXT NULL AFTER bio_encrypted');
    await addColumnIfMissing(database, 'users', 'banner_media_encrypted', 'ALTER TABLE users ADD COLUMN banner_media_encrypted LONGTEXT NULL AFTER avatar_media_encrypted');

    await database.query("UPDATE users SET user_id = UUID() WHERE user_id IS NULL OR user_id = ''");
    await database.query("UPDATE users SET role = 'user' WHERE role IS NULL OR role = ''");
    await database.query('UPDATE users SET email_verified = 1 WHERE email_verified IS NULL');
    await database.query('UPDATE users SET is_approved = 1 WHERE is_approved IS NULL');
    await database.query('UPDATE users SET is_banned = 0 WHERE is_banned IS NULL');
    await database.query('UPDATE users SET two_factor_enabled = 0 WHERE two_factor_enabled IS NULL');
    await database.query('UPDATE users SET force_password_reset = 0 WHERE force_password_reset IS NULL');

    const [emailRows] = await database.query('SELECT id, email_encrypted, email_hash, email_verified, email_verified_at, is_approved, approved_at FROM users');
    for (const row of emailRows) {
        const updates = [];
        const values = [];

        if (!row.email_hash) {
            updates.push('email_hash = ?');
            values.push(sha256(normalizeEmailAddress(decryptText(row.email_encrypted))));
        }

        if (row.email_verified && !row.email_verified_at) {
            updates.push('email_verified_at = ?');
            values.push(new Date());
        }

        if (row.is_approved && !row.approved_at) {
            updates.push('approved_at = ?');
            values.push(new Date());
        }

        if (!updates.length) {
            continue;
        }

        values.push(row.id);
        await database.query(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values);
    }
}

async function ensureProjectsTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS projects (
            id VARCHAR(64) PRIMARY KEY,
            owner_user_id INT NULL,
            title_encrypted TEXT NOT NULL,
            summary_encrypted LONGTEXT NOT NULL,
            description_encrypted LONGTEXT NOT NULL,
            type_encrypted TEXT NOT NULL,
            status_encrypted TEXT NOT NULL,
            visibility VARCHAR(16) NOT NULL DEFAULT 'public',
            featured TINYINT(1) NOT NULL DEFAULT 0,
            tags_encrypted LONGTEXT NULL,
            downloads_encrypted LONGTEXT NULL,
            screenshots_encrypted LONGTEXT NULL,
            changelog_encrypted LONGTEXT NULL,
            devlogs_encrypted LONGTEXT NULL,
            known_bugs_encrypted LONGTEXT NULL,
            external_links_encrypted LONGTEXT NULL,
            view_count INT NOT NULL DEFAULT 0,
            download_count INT NOT NULL DEFAULT 0,
            like_count INT NOT NULL DEFAULT 0,
            comment_count INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    `);

    await addColumnIfMissing(database, 'projects', 'visibility', "ALTER TABLE projects ADD COLUMN visibility VARCHAR(16) NOT NULL DEFAULT 'public' AFTER status_encrypted");
    await addColumnIfMissing(database, 'projects', 'featured', "ALTER TABLE projects ADD COLUMN featured TINYINT(1) NOT NULL DEFAULT 0 AFTER visibility");
    await addColumnIfMissing(database, 'projects', 'tags_encrypted', 'ALTER TABLE projects ADD COLUMN tags_encrypted LONGTEXT NULL AFTER featured');
    await addColumnIfMissing(database, 'projects', 'downloads_encrypted', 'ALTER TABLE projects ADD COLUMN downloads_encrypted LONGTEXT NULL AFTER tags_encrypted');
    await addColumnIfMissing(database, 'projects', 'screenshots_encrypted', 'ALTER TABLE projects ADD COLUMN screenshots_encrypted LONGTEXT NULL AFTER downloads_encrypted');
    await addColumnIfMissing(database, 'projects', 'changelog_encrypted', 'ALTER TABLE projects ADD COLUMN changelog_encrypted LONGTEXT NULL AFTER screenshots_encrypted');
    await addColumnIfMissing(database, 'projects', 'devlogs_encrypted', 'ALTER TABLE projects ADD COLUMN devlogs_encrypted LONGTEXT NULL AFTER changelog_encrypted');
    await addColumnIfMissing(database, 'projects', 'known_bugs_encrypted', 'ALTER TABLE projects ADD COLUMN known_bugs_encrypted LONGTEXT NULL AFTER devlogs_encrypted');
    await addColumnIfMissing(database, 'projects', 'external_links_encrypted', 'ALTER TABLE projects ADD COLUMN external_links_encrypted LONGTEXT NULL AFTER known_bugs_encrypted');
    await addColumnIfMissing(database, 'projects', 'view_count', 'ALTER TABLE projects ADD COLUMN view_count INT NOT NULL DEFAULT 0 AFTER external_links_encrypted');
    await addColumnIfMissing(database, 'projects', 'download_count', 'ALTER TABLE projects ADD COLUMN download_count INT NOT NULL DEFAULT 0 AFTER view_count');
    await addColumnIfMissing(database, 'projects', 'like_count', 'ALTER TABLE projects ADD COLUMN like_count INT NOT NULL DEFAULT 0 AFTER download_count');
    await addColumnIfMissing(database, 'projects', 'comment_count', 'ALTER TABLE projects ADD COLUMN comment_count INT NOT NULL DEFAULT 0 AFTER like_count');
    await addColumnIfMissing(database, 'projects', 'updated_at', 'ALTER TABLE projects ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER created_at');
}

async function ensureProjectMembersTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS project_members (
            project_id VARCHAR(64) NOT NULL,
            user_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (project_id, user_id),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
}

async function ensureSiteSettingsTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS site_settings (
            id TINYINT PRIMARY KEY,
            registrations_enabled TINYINT(1) NOT NULL DEFAULT 0,
            login_enabled TINYINT(1) NOT NULL DEFAULT 1,
            uploads_enabled TINYINT(1) NOT NULL DEFAULT 1,
            project_limit_enabled TINYINT(1) NOT NULL DEFAULT 0,
            max_projects_per_user INT NOT NULL DEFAULT 10,
            upload_size_limit_enabled TINYINT(1) NOT NULL DEFAULT 0,
            max_upload_size_mb INT NOT NULL DEFAULT 25,
            invite_only_enabled TINYINT(1) NOT NULL DEFAULT 0,
            approval_required TINYINT(1) NOT NULL DEFAULT 0,
            new_account_restrictions_enabled TINYINT(1) NOT NULL DEFAULT 0,
            new_account_restriction_hours INT NOT NULL DEFAULT 24,
            announcement_enabled TINYINT(1) NOT NULL DEFAULT 0,
            announcement_text_encrypted LONGTEXT NULL,
            announcement_link VARCHAR(255) NULL,
            trust_level_enabled TINYINT(1) NOT NULL DEFAULT 1,
            low_trust_age_hours INT NOT NULL DEFAULT 72,
            low_trust_comment_cooldown_seconds INT NOT NULL DEFAULT 45,
            low_trust_project_cooldown_minutes INT NOT NULL DEFAULT 30,
            word_blacklist_encrypted LONGTEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    `);

    await addColumnIfMissing(database, 'site_settings', 'registrations_enabled', 'ALTER TABLE site_settings ADD COLUMN registrations_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER id');
    await addColumnIfMissing(database, 'site_settings', 'login_enabled', 'ALTER TABLE site_settings ADD COLUMN login_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER registrations_enabled');
    await addColumnIfMissing(database, 'site_settings', 'uploads_enabled', 'ALTER TABLE site_settings ADD COLUMN uploads_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER login_enabled');
    await addColumnIfMissing(database, 'site_settings', 'project_limit_enabled', 'ALTER TABLE site_settings ADD COLUMN project_limit_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER uploads_enabled');
    await addColumnIfMissing(database, 'site_settings', 'max_projects_per_user', 'ALTER TABLE site_settings ADD COLUMN max_projects_per_user INT NOT NULL DEFAULT 10 AFTER project_limit_enabled');
    await addColumnIfMissing(database, 'site_settings', 'upload_size_limit_enabled', 'ALTER TABLE site_settings ADD COLUMN upload_size_limit_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER max_projects_per_user');
    await addColumnIfMissing(database, 'site_settings', 'max_upload_size_mb', 'ALTER TABLE site_settings ADD COLUMN max_upload_size_mb INT NOT NULL DEFAULT 25 AFTER upload_size_limit_enabled');
    await addColumnIfMissing(database, 'site_settings', 'invite_only_enabled', 'ALTER TABLE site_settings ADD COLUMN invite_only_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER max_upload_size_mb');
    await addColumnIfMissing(database, 'site_settings', 'approval_required', 'ALTER TABLE site_settings ADD COLUMN approval_required TINYINT(1) NOT NULL DEFAULT 0 AFTER invite_only_enabled');
    await addColumnIfMissing(database, 'site_settings', 'new_account_restrictions_enabled', 'ALTER TABLE site_settings ADD COLUMN new_account_restrictions_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER approval_required');
    await addColumnIfMissing(database, 'site_settings', 'new_account_restriction_hours', 'ALTER TABLE site_settings ADD COLUMN new_account_restriction_hours INT NOT NULL DEFAULT 24 AFTER new_account_restrictions_enabled');
    await addColumnIfMissing(database, 'site_settings', 'announcement_enabled', 'ALTER TABLE site_settings ADD COLUMN announcement_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER new_account_restriction_hours');
    await addColumnIfMissing(database, 'site_settings', 'announcement_text_encrypted', 'ALTER TABLE site_settings ADD COLUMN announcement_text_encrypted LONGTEXT NULL AFTER announcement_enabled');
    await addColumnIfMissing(database, 'site_settings', 'announcement_link', 'ALTER TABLE site_settings ADD COLUMN announcement_link VARCHAR(255) NULL AFTER announcement_text_encrypted');
    await addColumnIfMissing(database, 'site_settings', 'trust_level_enabled', 'ALTER TABLE site_settings ADD COLUMN trust_level_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER announcement_link');
    await addColumnIfMissing(database, 'site_settings', 'low_trust_age_hours', 'ALTER TABLE site_settings ADD COLUMN low_trust_age_hours INT NOT NULL DEFAULT 72 AFTER trust_level_enabled');
    await addColumnIfMissing(database, 'site_settings', 'low_trust_comment_cooldown_seconds', 'ALTER TABLE site_settings ADD COLUMN low_trust_comment_cooldown_seconds INT NOT NULL DEFAULT 45 AFTER low_trust_age_hours');
    await addColumnIfMissing(database, 'site_settings', 'low_trust_project_cooldown_minutes', 'ALTER TABLE site_settings ADD COLUMN low_trust_project_cooldown_minutes INT NOT NULL DEFAULT 30 AFTER low_trust_comment_cooldown_seconds');
    await addColumnIfMissing(database, 'site_settings', 'word_blacklist_encrypted', 'ALTER TABLE site_settings ADD COLUMN word_blacklist_encrypted LONGTEXT NULL AFTER low_trust_project_cooldown_minutes');

    await database.query(`
        INSERT INTO site_settings (
            id,
            registrations_enabled,
            login_enabled,
            uploads_enabled,
            project_limit_enabled,
            max_projects_per_user,
            upload_size_limit_enabled,
            max_upload_size_mb,
            invite_only_enabled,
            approval_required,
            new_account_restrictions_enabled,
            new_account_restriction_hours,
            announcement_enabled
        )
        VALUES (1, 0, 1, 1, 0, 10, 0, 25, 0, 0, 0, 24, 0)
        ON DUPLICATE KEY UPDATE id = id
    `);
}

async function ensureEmailVerificationTokensTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token_hash CHAR(64) NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
}

async function ensureInviteCodesTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS invite_codes (
            code VARCHAR(32) PRIMARY KEY,
            created_by_user_id INT NULL,
            uses_remaining INT NOT NULL DEFAULT 1,
            expires_at DATETIME NULL,
            is_disabled TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    `);
}

async function ensureCommentsTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS comments (
            id CHAR(36) PRIMARY KEY,
            project_id VARCHAR(64) NOT NULL,
            author_user_id INT NULL,
            content_encrypted LONGTEXT NOT NULL,
            is_hidden TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (author_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    `);
}

async function ensureReportsTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS reports (
            id CHAR(36) PRIMARY KEY,
            reporter_user_id INT NULL,
            target_type VARCHAR(32) NOT NULL,
            target_id VARCHAR(64) NOT NULL,
            reason VARCHAR(64) NOT NULL,
            details_encrypted LONGTEXT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'open',
            admin_note_encrypted LONGTEXT NULL,
            resolved_by_user_id INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME NULL,
            FOREIGN KEY (reporter_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (resolved_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    `);
}

async function ensureAuditLogsTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS audit_logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            actor_user_id INT NULL,
            action VARCHAR(64) NOT NULL,
            target_type VARCHAR(32) NOT NULL,
            target_id VARCHAR(64) NULL,
            details_encrypted LONGTEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    `);
}

async function ensureProjectLikesTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS project_likes (
            project_id VARCHAR(64) NOT NULL,
            user_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (project_id, user_id),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
}

async function ensureUserFollowsTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS user_follows (
            follower_user_id INT NOT NULL,
            followed_user_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (follower_user_id, followed_user_id),
            FOREIGN KEY (follower_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (followed_user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
}

async function ensureNotificationsTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS notifications (
            id CHAR(36) PRIMARY KEY,
            user_id INT NOT NULL,
            type VARCHAR(32) NOT NULL,
            message_encrypted LONGTEXT NOT NULL,
            link VARCHAR(255) NULL,
            is_read TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
}

async function ensureUploadedFilesTable(database) {
    await database.query(`
        CREATE TABLE IF NOT EXISTS uploaded_files (
            stored_name VARCHAR(128) PRIMARY KEY,
            owner_user_id INT NULL,
            target_type VARCHAR(32) NOT NULL,
            target_id VARCHAR(64) NULL,
            original_name_encrypted TEXT NULL,
            mime_type VARCHAR(128) NOT NULL DEFAULT 'application/octet-stream',
            size BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    `);
}

function mapSiteSettingsRow(row = {}) {
    return {
        registrationsEnabled: Boolean(row.registrations_enabled),
        loginEnabled: Boolean(row.login_enabled),
        uploadsEnabled: Boolean(row.uploads_enabled),
        projectLimitEnabled: Boolean(row.project_limit_enabled),
        maxProjectsPerUser: Math.max(1, Number(row.max_projects_per_user) || 10),
        uploadSizeLimitEnabled: Boolean(row.upload_size_limit_enabled),
        maxUploadSizeMb: Math.max(1, Number(row.max_upload_size_mb) || 25),
        inviteOnlyEnabled: Boolean(row.invite_only_enabled),
        approvalRequired: Boolean(row.approval_required),
        newAccountRestrictionsEnabled: Boolean(row.new_account_restrictions_enabled),
        newAccountRestrictionHours: Math.max(1, Number(row.new_account_restriction_hours) || 24),
        announcementEnabled: Boolean(row.announcement_enabled),
        announcementText: decryptText(row.announcement_text_encrypted),
        announcementLink: row.announcement_link || '',
        trustLevelEnabled: row.trust_level_enabled == null ? true : Boolean(row.trust_level_enabled),
        lowTrustAgeHours: Math.max(1, Number(row.low_trust_age_hours) || 72),
        lowTrustCommentCooldownSeconds: Math.max(0, Number(row.low_trust_comment_cooldown_seconds) || 45),
        lowTrustProjectCooldownMinutes: Math.max(0, Number(row.low_trust_project_cooldown_minutes) || 30),
        wordBlacklist: normalizeWordList(decryptJson(row.word_blacklist_encrypted)),
        updatedAt: row.updated_at
    };
}

function mapUserRow(row = {}) {
    const avatarMedia = normalizeProfileMedia(decryptText(row.avatar_media_encrypted), 'avatar');
    const bannerMedia = normalizeProfileMedia(decryptText(row.banner_media_encrypted), 'banner');
    const banExpiresAt = row.ban_expires_at || null;
    const isBanActive = Boolean(row.is_banned) && (!banExpiresAt || new Date(banExpiresAt).getTime() > Date.now());

    return {
        id: row.id,
        userId: row.user_id,
        username: row.username,
        email: decryptText(row.email_encrypted),
        passwordHash: row.password_hash,
        role: row.role,
        emailVerified: Boolean(row.email_verified),
        emailVerifiedAt: row.email_verified_at,
        isApproved: Boolean(row.is_approved),
        approvedAt: row.approved_at,
        isBanned: isBanActive,
        bannedAt: row.banned_at,
        banReason: decryptText(row.ban_reason_encrypted),
        banExpiresAt,
        twoFactorEnabled: Boolean(row.two_factor_enabled),
        twoFactorSecret: decryptText(row.two_factor_secret_encrypted),
        twoFactorBackupCodeHashes: decryptJson(row.two_factor_backup_codes_encrypted),
        twoFactorConfirmedAt: row.two_factor_confirmed_at,
        forcePasswordReset: Boolean(row.force_password_reset),
        bio: decryptText(row.bio_encrypted),
        avatarMedia,
        bannerMedia,
        createdAt: row.created_at,
        projectCount: row.project_count != null ? Number(row.project_count) : undefined,
        followerCount: row.follower_count != null ? Number(row.follower_count) : undefined,
        followingCount: row.following_count != null ? Number(row.following_count) : undefined
    };
}

async function clearExpiredBans(database) {
    await database.query(
        `
            UPDATE users
            SET is_banned = 0,
                banned_at = NULL,
                ban_reason_encrypted = NULL,
                ban_expires_at = NULL
            WHERE is_banned = 1
              AND ban_expires_at IS NOT NULL
              AND ban_expires_at <= NOW()
        `
    );
}

function mapProjectRow(row = {}) {
    return {
        id: row.id,
        title: decryptText(row.title_encrypted),
        summary: decryptText(row.summary_encrypted),
        description: decryptText(row.description_encrypted),
        type: decryptText(row.type_encrypted),
        status: decryptText(row.status_encrypted),
        visibility: normalizeVisibility(row.visibility),
        featured: Boolean(row.featured),
        tags: normalizeTags(decryptJson(row.tags_encrypted)),
        downloadables: normalizeFileEntries(decryptJson(row.downloads_encrypted), 'attachment'),
        screenshots: normalizeFileEntries(decryptJson(row.screenshots_encrypted), 'screenshot'),
        changelog: normalizeChangelog(decryptJson(row.changelog_encrypted)),
        devlogs: normalizeDevlogs(decryptJson(row.devlogs_encrypted)),
        knownBugs: normalizeKnownBugs(decryptJson(row.known_bugs_encrypted)),
        externalLinks: normalizeExternalLinks(decryptJson(row.external_links_encrypted)),
        viewCount: Number(row.view_count) || 0,
        downloadCount: Number(row.download_count) || 0,
        likeCount: Number(row.like_count) || 0,
        commentCount: Number(row.comment_count) || 0,
        owner: row.owner_username || 'Deleted User',
        ownerUserId: row.owner_public_user_id || null,
        ownerDbId: row.owner_user_id || null,
        ownerAvatarMedia: normalizeProfileMedia(decryptText(row.owner_avatar_media_encrypted), 'avatar'),
        owners: [],
        ownerDbIds: row.owner_user_id ? [Number(row.owner_user_id)] : [],
        createdAt: row.created_at,
        updatedAt: row.updated_at
    };
}

function mapCommentRow(row = {}) {
    return {
        id: row.id,
        projectId: row.project_id,
        authorUserId: row.author_public_user_id || null,
        author: row.author_username || 'Deleted User',
        authorAvatarMedia: normalizeProfileMedia(decryptText(row.author_avatar_media_encrypted), 'avatar'),
        content: decryptText(row.content_encrypted),
        isHidden: Boolean(row.is_hidden),
        createdAt: row.created_at,
        updatedAt: row.updated_at
    };
}

function mapReportRow(row = {}) {
    return {
        id: row.id,
        targetType: row.target_type,
        targetId: row.target_id,
        reason: row.reason,
        details: decryptText(row.details_encrypted),
        status: row.status,
        adminNote: decryptText(row.admin_note_encrypted),
        reporterUserId: row.reporter_public_user_id || null,
        reporter: row.reporter_username || 'Deleted User',
        resolvedByUserId: row.resolved_by_public_user_id || null,
        resolvedBy: row.resolved_by_username || null,
        createdAt: row.created_at,
        resolvedAt: row.resolved_at
    };
}

function mapAuditLogRow(row = {}) {
    return {
        id: row.id,
        actorUserId: row.actor_public_user_id || null,
        actor: row.actor_username || 'System',
        action: row.action,
        targetType: row.target_type,
        targetId: row.target_id,
        details: decryptText(row.details_encrypted),
        createdAt: row.created_at
    };
}

function mapNotificationRow(row = {}) {
    return {
        id: row.id,
        type: row.type,
        message: decryptText(row.message_encrypted),
        link: row.link || '',
        isRead: Boolean(row.is_read),
        createdAt: row.created_at
    };
}

function mapUploadedFileRow(row = {}) {
    return {
        storedName: row.stored_name,
        ownerUserId: row.owner_user_id,
        targetType: row.target_type,
        targetId: row.target_id,
        originalName: decryptText(row.original_name_encrypted),
        mimeType: row.mime_type,
        size: Number(row.size) || 0,
        createdAt: row.created_at
    };
}

function getUserProjectCountSql(alias = 'users') {
    return `(SELECT COUNT(DISTINCT p.id) FROM projects p LEFT JOIN project_members pm ON pm.project_id = p.id WHERE p.owner_user_id = ${alias}.id OR pm.user_id = ${alias}.id)`;
}

async function getProjectOwnersMap(projectIds = []) {
    const ids = [...new Set(projectIds.map((entry) => String(entry || '').trim()).filter(Boolean))];
    if (!ids.length) {
        return new Map();
    }

    const database = getPool();
    const placeholders = ids.map(() => '?').join(', ');
    const [rows] = await database.query(
        `
            SELECT project_members.project_id,
                   users.id AS member_db_id,
                   users.user_id AS member_public_user_id,
                   users.username AS member_username,
                   users.role AS member_role,
                   users.avatar_media_encrypted AS member_avatar_media_encrypted
            FROM project_members
            INNER JOIN users ON users.id = project_members.user_id
            WHERE project_members.project_id IN (${placeholders})
            ORDER BY project_members.created_at ASC
        `,
        ids
    );

    const ownersMap = new Map();
    for (const row of rows) {
        const owners = ownersMap.get(row.project_id) || [];
        owners.push({
            dbId: Number(row.member_db_id) || null,
            userId: row.member_public_user_id || null,
            username: row.member_username || 'Deleted User',
            role: row.member_role || 'user',
            avatarMedia: normalizeProfileMedia(decryptText(row.member_avatar_media_encrypted), 'avatar'),
            isPrimary: false
        });
        ownersMap.set(row.project_id, owners);
    }

    return ownersMap;
}

async function hydrateProjectsWithOwners(projects = []) {
    if (!projects.length) {
        return projects;
    }

    const ownersMap = await getProjectOwnersMap(projects.map((project) => project.id));
    return projects.map((project) => {
        const owners = [];
        const seen = new Set();

        if (project.ownerDbId) {
            const key = `db:${project.ownerDbId}`;
            seen.add(key);
            owners.push({
                dbId: project.ownerDbId,
                userId: project.ownerUserId || null,
                username: project.owner || 'Deleted User',
                role: 'owner',
                avatarMedia: project.ownerAvatarMedia || null,
                isPrimary: true
            });
        }

        for (const owner of ownersMap.get(project.id) || []) {
            const key = owner.dbId ? `db:${owner.dbId}` : `user:${owner.userId}`;
            if (seen.has(key)) {
                continue;
            }
            seen.add(key);
            owners.push(owner);
        }

        return {
            ...project,
            owners,
            ownerDbIds: owners.map((owner) => owner.dbId).filter(Boolean)
        };
    });
}

async function ensureBootstrapAdmin(database) {
    const config = getBootstrapAdminConfig();
    if (!config) {
        return;
    }

    const [adminRows] = await database.query("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
    if (adminRows[0]) {
        return;
    }

    const [existingRows] = await database.query('SELECT id FROM users WHERE username = ? LIMIT 1', [config.username]);
    const passwordHash = hashPassword(config.password);
    const encryptedEmail = encryptText(config.email);
    const emailHash = sha256(normalizeEmailAddress(config.email));

    if (existingRows[0]) {
        await database.query(
            `
                UPDATE users
                SET email_encrypted = ?,
                    email_hash = ?,
                    password_hash = ?,
                    role = 'admin',
                    email_verified = 1,
                    email_verified_at = ?,
                    is_approved = 1,
                    approved_at = ?,
                    is_banned = 0,
                    banned_at = NULL,
                    force_password_reset = 0
                WHERE id = ?
            `,
            [encryptedEmail, emailHash, passwordHash, new Date(), new Date(), existingRows[0].id]
        );
        return;
    }

    await database.query(
        `
            INSERT INTO users (
                user_id,
                username,
                email_encrypted,
                email_hash,
                password_hash,
                role,
                email_verified,
                email_verified_at,
                is_approved,
                approved_at
            )
            VALUES (?, ?, ?, ?, ?, 'admin', 1, ?, 1, ?)
        `,
        [crypto.randomUUID(), config.username, encryptedEmail, emailHash, passwordHash, new Date(), new Date()]
    );
}

async function syncProjectFileIndex(projectId, ownerUserId, attachments = [], screenshots = []) {
    const database = getPool();
    await database.query(
        "DELETE FROM uploaded_files WHERE target_type IN ('project_attachment', 'project_screenshot') AND target_id = ?",
        [projectId]
    );

    const entries = [
        ...attachments.map((entry) => ({ ...entry, targetType: 'project_attachment' })),
        ...screenshots.map((entry) => ({ ...entry, targetType: 'project_screenshot' }))
    ];

    for (const entry of entries) {
        await database.query(
            `
                INSERT INTO uploaded_files (
                    stored_name,
                    owner_user_id,
                    target_type,
                    target_id,
                    original_name_encrypted,
                    mime_type,
                    size
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `,
            [
                entry.storedName,
                ownerUserId,
                entry.targetType,
                projectId,
                encryptText(entry.name),
                entry.mimeType || 'application/octet-stream',
                Number(entry.size) || 0
            ]
        );
    }
}

async function replaceProjectMembers(projectId, ownerUserId, memberUserIds = []) {
    const database = getPool();
    const normalizedMemberIds = [...new Set((memberUserIds || [])
        .map((entry) => Number(entry))
        .filter((entry) => Number.isFinite(entry) && entry > 0 && entry !== ownerUserId))];

    await database.query('DELETE FROM project_members WHERE project_id = ?', [projectId]);

    for (const memberUserId of normalizedMemberIds) {
        await database.query(
            'INSERT IGNORE INTO project_members (project_id, user_id) VALUES (?, ?)',
            [projectId, memberUserId]
        );
    }
}

async function syncUserMediaIndex(userDbId, avatarMedia, bannerMedia) {
    const database = getPool();
    await database.query(
        "DELETE FROM uploaded_files WHERE target_type IN ('user_avatar', 'user_banner') AND target_id = ?",
        [String(userDbId)]
    );

    const entries = [];
    if (avatarMedia) {
        entries.push({ ...avatarMedia, targetType: 'user_avatar' });
    }
    if (bannerMedia) {
        entries.push({ ...bannerMedia, targetType: 'user_banner' });
    }

    for (const entry of entries) {
        await database.query(
            `
                INSERT INTO uploaded_files (
                    stored_name,
                    owner_user_id,
                    target_type,
                    target_id,
                    original_name_encrypted,
                    mime_type,
                    size
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `,
            [
                entry.storedName,
                userDbId,
                entry.targetType,
                String(userDbId),
                encryptText(entry.name),
                entry.mimeType || 'application/octet-stream',
                Number(entry.size) || 0
            ]
        );
    }
}

async function synchronizeUploadedFilesFromExistingRows(database) {
    const [projectRows] = await database.query('SELECT id, owner_user_id, downloads_encrypted, screenshots_encrypted FROM projects');
    for (const row of projectRows) {
        const attachments = normalizeFileEntries(decryptJson(row.downloads_encrypted), 'attachment');
        const screenshots = normalizeFileEntries(decryptJson(row.screenshots_encrypted), 'screenshot');
        await syncProjectFileIndex(row.id, row.owner_user_id, attachments, screenshots);
    }

    const [userRows] = await database.query('SELECT id, avatar_media_encrypted, banner_media_encrypted FROM users');
    for (const row of userRows) {
        const avatarMedia = normalizeProfileMedia(decryptText(row.avatar_media_encrypted), 'avatar');
        const bannerMedia = normalizeProfileMedia(decryptText(row.banner_media_encrypted), 'banner');
        await syncUserMediaIndex(row.id, avatarMedia, bannerMedia);
    }
}

async function initializeDatabase() {
    const database = getPool();
    await ensureUsersTable(database);
    await ensureBootstrapAdmin(database);
    await ensureProjectsTable(database);
    await ensureProjectMembersTable(database);
    await ensureSiteSettingsTable(database);
    await ensureEmailVerificationTokensTable(database);
    await ensureInviteCodesTable(database);
    await ensureCommentsTable(database);
    await ensureReportsTable(database);
    await ensureAuditLogsTable(database);
    await ensureProjectLikesTable(database);
    await ensureUserFollowsTable(database);
    await ensureNotificationsTable(database);
    await ensureUploadedFilesTable(database);
    await database.query(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token_hash CHAR(64) NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    await database.query(`
        DELETE FROM projects
        WHERE id IN ('pixel-runner', 'dev-notes', 'portfolio-kit')
    `);

    await synchronizeUploadedFilesFromExistingRows(database);
}

async function createUser({
    username,
    email,
    password,
    role = 'user',
    emailVerified = true,
    isApproved = true
}) {
    const database = getPool();
    const userId = crypto.randomUUID();
    const passwordHash = hashPassword(password);
    const normalizedEmail = normalizeEmailAddress(email);
    const now = new Date();
    const [result] = await database.query(
        `
            INSERT INTO users (
                user_id,
                username,
                email_encrypted,
                email_hash,
                password_hash,
                role,
                email_verified,
                email_verified_at,
                is_approved,
                approved_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
            userId,
            username,
            encryptText(email),
            sha256(normalizedEmail),
            passwordHash,
            role,
            emailVerified ? 1 : 0,
            emailVerified ? now : null,
            isApproved ? 1 : 0,
            isApproved ? now : null
        ]
    );

    return findUserById(result.insertId);
}

async function updateUserProfile(userDbId, { bio, avatarMedia, bannerMedia }) {
    const database = getPool();
    const normalizedAvatar = normalizeProfileMedia(avatarMedia, 'avatar');
    const normalizedBanner = normalizeProfileMedia(bannerMedia, 'banner');

    await database.query(
        `
            UPDATE users
            SET bio_encrypted = ?,
                avatar_media_encrypted = ?,
                banner_media_encrypted = ?
            WHERE id = ?
        `,
        [
            encryptText(String(bio || '').trim()),
            encryptText(normalizedAvatar ? JSON.stringify(normalizedAvatar) : ''),
            encryptText(normalizedBanner ? JSON.stringify(normalizedBanner) : ''),
            userDbId
        ]
    );

    await syncUserMediaIndex(userDbId, normalizedAvatar, normalizedBanner);
    return findUserById(userDbId);
}

async function updateUserPassword(userDbId, password) {
    const database = getPool();
    await database.query(
        `
            UPDATE users
            SET password_hash = ?,
                force_password_reset = 0
            WHERE id = ?
        `,
        [hashPassword(password), userDbId]
    );

    return findUserById(userDbId);
}

async function findUserById(userDbId) {
    const database = getPool();
    await clearExpiredBans(database);
    const [rows] = await database.query(
        `
            SELECT users.*,
                   ${getUserProjectCountSql('users')} AS project_count,
                   (SELECT COUNT(*) FROM user_follows WHERE followed_user_id = users.id) AS follower_count,
                   (SELECT COUNT(*) FROM user_follows WHERE follower_user_id = users.id) AS following_count
            FROM users
            WHERE users.id = ?
            LIMIT 1
        `,
        [userDbId]
    );

    return rows[0] ? mapUserRow(rows[0]) : null;
}

async function findUserByUsername(username) {
    const database = getPool();
    await clearExpiredBans(database);
    const [rows] = await database.query(
        `
            SELECT users.*,
                   ${getUserProjectCountSql('users')} AS project_count,
                   (SELECT COUNT(*) FROM user_follows WHERE followed_user_id = users.id) AS follower_count,
                   (SELECT COUNT(*) FROM user_follows WHERE follower_user_id = users.id) AS following_count
            FROM users
            WHERE users.username = ?
            LIMIT 1
        `,
        [username]
    );

    return rows[0] ? mapUserRow(rows[0]) : null;
}

async function findUserByEmail(email) {
    const database = getPool();
    await clearExpiredBans(database);
    const [rows] = await database.query(
        `
            SELECT users.*,
                   ${getUserProjectCountSql('users')} AS project_count,
                   (SELECT COUNT(*) FROM user_follows WHERE followed_user_id = users.id) AS follower_count,
                   (SELECT COUNT(*) FROM user_follows WHERE follower_user_id = users.id) AS following_count
            FROM users
            WHERE users.email_hash = ?
            LIMIT 1
        `,
        [sha256(normalizeEmailAddress(email))]
    );

    return rows[0] ? mapUserRow(rows[0]) : null;
}

async function findUserByPublicId(userId) {
    const database = getPool();
    await clearExpiredBans(database);
    const [rows] = await database.query(
        `
            SELECT users.*,
                   ${getUserProjectCountSql('users')} AS project_count,
                   (SELECT COUNT(*) FROM user_follows WHERE followed_user_id = users.id) AS follower_count,
                   (SELECT COUNT(*) FROM user_follows WHERE follower_user_id = users.id) AS following_count
            FROM users
            WHERE users.user_id = ?
            LIMIT 1
        `,
        [userId]
    );

    return rows[0] ? mapUserRow(rows[0]) : null;
}

async function findUsersByUsernames(usernames = []) {
    const normalized = [...new Set((usernames || []).map((entry) => String(entry || '').trim()).filter(Boolean))];
    if (!normalized.length) {
        return [];
    }

    const database = getPool();
    await clearExpiredBans(database);
    const placeholders = normalized.map(() => '?').join(', ');
    const [rows] = await database.query(
        `
            SELECT users.*,
                   ${getUserProjectCountSql('users')} AS project_count,
                   (SELECT COUNT(*) FROM user_follows WHERE followed_user_id = users.id) AS follower_count,
                   (SELECT COUNT(*) FROM user_follows WHERE follower_user_id = users.id) AS following_count
            FROM users
            WHERE users.username IN (${placeholders})
        `,
        normalized
    );

    const usersByUsername = new Map(rows.map((row) => [row.username, mapUserRow(row)]));
    return normalized.map((username) => usersByUsername.get(username)).filter(Boolean);
}

async function createSession(userId) {
    const database = getPool();
    const rawToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + sessionTtlHours * 60 * 60 * 1000);
    await database.query(
        'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
        [userId, sha256(rawToken), expiresAt]
    );

    return { token: rawToken, expiresAt };
}

async function createEmailVerificationToken(userDbId, ttlHours = 24) {
    const database = getPool();
    const rawToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000);
    await database.query('DELETE FROM email_verification_tokens WHERE user_id = ?', [userDbId]);
    await database.query(
        'INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
        [userDbId, sha256(rawToken), expiresAt]
    );
    return { token: rawToken, expiresAt };
}

async function findUserByEmailVerificationToken(rawToken) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT users.*,
                   tokens.expires_at,
                   (SELECT COUNT(*) FROM projects WHERE owner_user_id = users.id) AS project_count,
                   (SELECT COUNT(*) FROM user_follows WHERE followed_user_id = users.id) AS follower_count,
                   (SELECT COUNT(*) FROM user_follows WHERE follower_user_id = users.id) AS following_count
            FROM email_verification_tokens tokens
            INNER JOIN users ON users.id = tokens.user_id
            WHERE tokens.token_hash = ?
            LIMIT 1
        `,
        [sha256(String(rawToken || ''))]
    );

    if (!rows[0]) {
        return null;
    }

    if (new Date(rows[0].expires_at).getTime() < Date.now()) {
        await database.query('DELETE FROM email_verification_tokens WHERE token_hash = ?', [sha256(String(rawToken || ''))]);
        return null;
    }

    return mapUserRow(rows[0]);
}

async function markUserEmailVerified(userDbId) {
    const database = getPool();
    await database.query(
        `
            UPDATE users
            SET email_verified = 1,
                email_verified_at = COALESCE(email_verified_at, ?)
            WHERE id = ?
        `,
        [new Date(), userDbId]
    );
    await database.query('DELETE FROM email_verification_tokens WHERE user_id = ?', [userDbId]);
    return findUserById(userDbId);
}

async function setUserApprovalStatus(userId, approved) {
    const database = getPool();
    await database.query(
        `
            UPDATE users
            SET is_approved = ?,
                approved_at = ?
            WHERE user_id = ?
        `,
        [approved ? 1 : 0, approved ? new Date() : null, userId]
    );
    return findUserByPublicId(userId);
}

function generateInviteCode(length = 12) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let value = '';
    for (let index = 0; index < length; index += 1) {
        value += alphabet[Math.floor(Math.random() * alphabet.length)];
    }
    return value;
}

async function createInviteCode({ createdByUserId, usesRemaining = 1, expiresAt = null }) {
    const database = getPool();
    let code = generateInviteCode();
    while (await getInviteCode(code)) {
        code = generateInviteCode();
    }

    await database.query(
        `
            INSERT INTO invite_codes (code, created_by_user_id, uses_remaining, expires_at, is_disabled)
            VALUES (?, ?, ?, ?, 0)
        `,
        [code, createdByUserId || null, Math.max(1, Number(usesRemaining) || 1), expiresAt]
    );
    return getInviteCode(code);
}

async function getInviteCode(code) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT invite_codes.*,
                   users.username AS created_by_username
            FROM invite_codes
            LEFT JOIN users ON users.id = invite_codes.created_by_user_id
            WHERE invite_codes.code = ?
            LIMIT 1
        `,
        [String(code || '').trim().toUpperCase()]
    );
    return rows[0]
        ? {
            code: rows[0].code,
            createdBy: rows[0].created_by_username || 'System',
            usesRemaining: Number(rows[0].uses_remaining) || 0,
            expiresAt: rows[0].expires_at,
            isDisabled: Boolean(rows[0].is_disabled),
            createdAt: rows[0].created_at
        }
        : null;
}

async function listInviteCodes() {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT invite_codes.*,
                   users.username AS created_by_username
            FROM invite_codes
            LEFT JOIN users ON users.id = invite_codes.created_by_user_id
            ORDER BY invite_codes.created_at DESC
        `
    );
    return rows.map((row) => ({
        code: row.code,
        createdBy: row.created_by_username || 'System',
        usesRemaining: Number(row.uses_remaining) || 0,
        expiresAt: row.expires_at,
        isDisabled: Boolean(row.is_disabled),
        createdAt: row.created_at
    }));
}

async function consumeInviteCode(code) {
    const database = getPool();
    const normalizedCode = String(code || '').trim().toUpperCase();
    const [result] = await database.query(
        `
            UPDATE invite_codes
            SET uses_remaining = uses_remaining - 1
            WHERE code = ?
              AND is_disabled = 0
              AND uses_remaining > 0
              AND (expires_at IS NULL OR expires_at > NOW())
        `,
        [normalizedCode]
    );

    if (!result.affectedRows) {
        return null;
    }

    await database.query('DELETE FROM invite_codes WHERE code = ? AND uses_remaining <= 0', [normalizedCode]);
    return true;
}

async function revokeInviteCode(code) {
    const database = getPool();
    await database.query('UPDATE invite_codes SET is_disabled = 1 WHERE code = ?', [String(code || '').trim().toUpperCase()]);
}

async function findUserBySessionToken(token) {
    const database = getPool();
    await clearExpiredBans(database);
    const [rows] = await database.query(
        `
            SELECT users.*,
                   ${getUserProjectCountSql('users')} AS project_count,
                   (SELECT COUNT(*) FROM user_follows WHERE followed_user_id = users.id) AS follower_count,
                   (SELECT COUNT(*) FROM user_follows WHERE follower_user_id = users.id) AS following_count
            FROM sessions
            INNER JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > NOW()
            LIMIT 1
        `,
        [sha256(token)]
    );

    return rows[0] ? mapUserRow(rows[0]) : null;
}

async function deleteSession(token) {
    const database = getPool();
    await database.query('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
}

async function deleteSessionsForUser(userDbId) {
    const database = getPool();
    await database.query('DELETE FROM sessions WHERE user_id = ?', [userDbId]);
}

async function storePendingTwoFactorSecret(userDbId, secret) {
    const database = getPool();
    await database.query(
        `
            UPDATE users
            SET two_factor_enabled = 0,
                two_factor_secret_encrypted = ?,
                two_factor_backup_codes_encrypted = NULL,
                two_factor_confirmed_at = NULL
            WHERE id = ?
        `,
        [encryptText(secret), userDbId]
    );
}

async function enableUserTwoFactor(userDbId, secret, backupCodeHashes) {
    const database = getPool();
    await database.query(
        `
            UPDATE users
            SET two_factor_enabled = 1,
                two_factor_secret_encrypted = ?,
                two_factor_backup_codes_encrypted = ?,
                two_factor_confirmed_at = ?
            WHERE id = ?
        `,
        [encryptText(secret), encryptJson(backupCodeHashes), new Date(), userDbId]
    );
}

async function replaceUserTwoFactorBackupCodes(userDbId, backupCodeHashes) {
    const database = getPool();
    await database.query(
        'UPDATE users SET two_factor_backup_codes_encrypted = ? WHERE id = ?',
        [encryptJson(backupCodeHashes), userDbId]
    );
}

async function disableUserTwoFactor(userDbId) {
    const database = getPool();
    await database.query(
        `
            UPDATE users
            SET two_factor_enabled = 0,
                two_factor_secret_encrypted = NULL,
                two_factor_backup_codes_encrypted = NULL,
                two_factor_confirmed_at = NULL
            WHERE id = ?
        `,
        [userDbId]
    );
}

async function getAllUsers() {
    const database = getPool();
    await clearExpiredBans(database);
    const [rows] = await database.query(`
        SELECT users.*,
               ${getUserProjectCountSql('users')} AS project_count,
               (SELECT COUNT(*) FROM user_follows WHERE followed_user_id = users.id) AS follower_count,
               (SELECT COUNT(*) FROM user_follows WHERE follower_user_id = users.id) AS following_count
        FROM users
        ORDER BY users.created_at DESC
    `);

    return rows.map(mapUserRow);
}

async function setUserBanStatus(userId, banned, options = {}) {
    const database = getPool();
    const banReason = String(options.reason || '').trim();
    const banHours = Number(options.hours);
    const banExpiresAt = banned && Number.isFinite(banHours) && banHours > 0
        ? new Date(Date.now() + Math.floor(banHours) * 60 * 60 * 1000)
        : null;
    const [result] = await database.query(
        `
            UPDATE users
            SET is_banned = ?,
                banned_at = ?,
                ban_reason_encrypted = ?,
                ban_expires_at = ?
            WHERE user_id = ?
        `,
        [
            banned ? 1 : 0,
            banned ? new Date() : null,
            banned && banReason ? encryptText(banReason) : null,
            banExpiresAt,
            userId
        ]
    );

    return result.affectedRows > 0;
}

async function countAdmins(excludingUserDbId = null) {
    const database = getPool();
    if (excludingUserDbId) {
        const [rows] = await database.query(
            "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND id <> ?",
            [excludingUserDbId]
        );
        return Number(rows[0].count) || 0;
    }

    const [rows] = await database.query("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'");
    return Number(rows[0].count) || 0;
}

async function setUserRole(userId, role) {
    const database = getPool();
    await database.query('UPDATE users SET role = ? WHERE user_id = ?', [role, userId]);
    return findUserByPublicId(userId);
}

async function setUserForcePasswordReset(userId, force) {
    const database = getPool();
    await database.query('UPDATE users SET force_password_reset = ? WHERE user_id = ?', [force ? 1 : 0, userId]);
    return findUserByPublicId(userId);
}

async function deleteUserByPublicId(userId) {
    const database = getPool();
    await database.query('DELETE FROM users WHERE user_id = ?', [userId]);
}

async function createAuditLog({ actorUserId = null, action, targetType, targetId = null, details = '' }) {
    const database = getPool();
    await database.query(
        `
            INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details_encrypted)
            VALUES (?, ?, ?, ?, ?)
        `,
        [actorUserId, action, targetType, targetId, encryptText(typeof details === 'string' ? details : JSON.stringify(details))]
    );
}

async function getAuditLogs(limit = 100) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT audit_logs.*, users.username AS actor_username, users.user_id AS actor_public_user_id
            FROM audit_logs
            LEFT JOIN users ON users.id = audit_logs.actor_user_id
            ORDER BY audit_logs.created_at DESC, audit_logs.id DESC
            LIMIT ?
        `,
        [Math.max(1, Number(limit) || 100)]
    );

    return rows.map(mapAuditLogRow);
}

async function createNotification({ userId, type, message, link = '' }) {
    const database = getPool();
    await database.query(
        `
            INSERT INTO notifications (id, user_id, type, message_encrypted, link)
            VALUES (?, ?, ?, ?, ?)
        `,
        [crypto.randomUUID(), userId, type, encryptText(message), String(link || '').trim().slice(0, 255)]
    );
}

async function getNotificationsForUser(userDbId) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 100
        `,
        [userDbId]
    );

    return rows.map(mapNotificationRow);
}

async function markAllNotificationsRead(userDbId) {
    const database = getPool();
    await database.query('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [userDbId]);
}

async function createProject({
    ownerUserId,
    coOwnerUserIds = [],
    title,
    summary,
    description,
    type,
    status,
    visibility,
    tags,
    downloadables,
    screenshots,
    changelog,
    devlogs,
    knownBugs,
    externalLinks,
    featured = false
}) {
    const database = getPool();
    const projectId = crypto.randomUUID();
    const normalizedAttachments = normalizeFileEntries(downloadables, 'attachment');
    const normalizedScreenshots = normalizeFileEntries(screenshots, 'screenshot');
    const normalizedChangelog = normalizeChangelog(changelog);
    const normalizedDevlogs = normalizeDevlogs(devlogs);
    const normalizedKnownBugs = normalizeKnownBugs(knownBugs);
    const normalizedExternalLinks = normalizeExternalLinks(externalLinks);
    const normalizedTags = normalizeTags(tags);

    await database.query(
        `
            INSERT INTO projects (
                id,
                owner_user_id,
                title_encrypted,
                summary_encrypted,
                description_encrypted,
                type_encrypted,
                status_encrypted,
                visibility,
                featured,
                tags_encrypted,
                downloads_encrypted,
                screenshots_encrypted,
                changelog_encrypted,
                devlogs_encrypted,
                known_bugs_encrypted,
                external_links_encrypted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
            projectId,
            ownerUserId,
            encryptText(title),
            encryptText(summary),
            encryptText(description),
            encryptText(type),
            encryptText(status),
            normalizeVisibility(visibility),
            featured ? 1 : 0,
            encryptJson(normalizedTags),
            encryptJson(normalizedAttachments),
            encryptJson(normalizedScreenshots),
            encryptJson(normalizedChangelog),
            encryptJson(normalizedDevlogs),
            encryptJson(normalizedKnownBugs),
            encryptJson(normalizedExternalLinks)
        ]
    );

    await replaceProjectMembers(projectId, ownerUserId, coOwnerUserIds);
    await syncProjectFileIndex(projectId, ownerUserId, normalizedAttachments, normalizedScreenshots);
    return getProjectById(projectId);
}

async function updateProject(projectId, {
    title,
    summary,
    description,
    type,
    status,
    visibility,
    tags,
    downloadables,
    screenshots,
    changelog,
    devlogs,
    knownBugs,
    externalLinks,
    coOwnerUserIds,
    featured
}) {
    const database = getPool();
    const existingProject = await getProjectById(projectId);
    const normalizedAttachments = normalizeFileEntries(downloadables, 'attachment');
    const normalizedScreenshots = normalizeFileEntries(screenshots, 'screenshot');
    const normalizedChangelog = normalizeChangelog(changelog);
    const normalizedDevlogs = normalizeDevlogs(devlogs);
    const normalizedKnownBugs = normalizeKnownBugs(knownBugs);
    const normalizedExternalLinks = normalizeExternalLinks(externalLinks);
    const normalizedTags = normalizeTags(tags);

    await database.query(
        `
            UPDATE projects
            SET title_encrypted = ?,
                summary_encrypted = ?,
                description_encrypted = ?,
                type_encrypted = ?,
                status_encrypted = ?,
                visibility = ?,
                featured = ?,
                tags_encrypted = ?,
                downloads_encrypted = ?,
                screenshots_encrypted = ?,
                changelog_encrypted = ?,
                devlogs_encrypted = ?,
                known_bugs_encrypted = ?,
                external_links_encrypted = ?
            WHERE id = ?
        `,
        [
            encryptText(title),
            encryptText(summary),
            encryptText(description),
            encryptText(type),
            encryptText(status),
            normalizeVisibility(visibility),
            featured ? 1 : 0,
            encryptJson(normalizedTags),
            encryptJson(normalizedAttachments),
            encryptJson(normalizedScreenshots),
            encryptJson(normalizedChangelog),
            encryptJson(normalizedDevlogs),
            encryptJson(normalizedKnownBugs),
            encryptJson(normalizedExternalLinks),
            projectId
        ]
    );

    await replaceProjectMembers(projectId, existingProject ? existingProject.ownerDbId : null, coOwnerUserIds ?? []);
    await syncProjectFileIndex(projectId, existingProject ? existingProject.ownerDbId : null, normalizedAttachments, normalizedScreenshots);
    return getProjectById(projectId);
}

async function getProjects(options = {}) {
    const database = getPool();
    const conditions = [];
    const params = [];

    if (options.ownerUserId != null) {
        conditions.push('(projects.owner_user_id = ? OR EXISTS (SELECT 1 FROM project_members WHERE project_members.project_id = projects.id AND project_members.user_id = ?))');
        params.push(options.ownerUserId, options.ownerUserId);
    }

    if (options.publicOnly) {
        conditions.push("projects.visibility = 'public'");
    }

    if (options.featuredOnly) {
        conditions.push('projects.featured = 1');
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limitClause = options.limit ? 'LIMIT ?' : '';
    if (options.limit) {
        params.push(Math.max(1, Number(options.limit) || 10));
    }

    const [rows] = await database.query(
        `
            SELECT projects.*,
                   users.username AS owner_username,
                   users.user_id AS owner_public_user_id,
                   users.avatar_media_encrypted AS owner_avatar_media_encrypted
            FROM projects
            LEFT JOIN users ON users.id = projects.owner_user_id
            ${whereClause}
            ORDER BY projects.featured DESC, projects.updated_at DESC, projects.created_at DESC
            ${limitClause}
        `,
        params
    );

    return hydrateProjectsWithOwners(rows.map(mapProjectRow));
}

async function getProjectById(id) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT projects.*,
                   users.username AS owner_username,
                   users.user_id AS owner_public_user_id,
                   users.avatar_media_encrypted AS owner_avatar_media_encrypted
            FROM projects
            LEFT JOIN users ON users.id = projects.owner_user_id
            WHERE projects.id = ?
            LIMIT 1
        `,
        [id]
    );

    if (!rows[0]) {
        return null;
    }

    const [project] = await hydrateProjectsWithOwners([mapProjectRow(rows[0])]);
    return project || null;
}

async function getProjectsForUser(ownerUserId) {
    return getProjects({ ownerUserId });
}

async function countProjectsForUser(ownerUserId) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT COUNT(DISTINCT projects.id) AS count
            FROM projects
            LEFT JOIN project_members ON project_members.project_id = projects.id
            WHERE projects.owner_user_id = ? OR project_members.user_id = ?
        `,
        [ownerUserId, ownerUserId]
    );

    return Number(rows[0].count) || 0;
}

async function deleteProject(projectId) {
    const database = getPool();
    await database.query('DELETE FROM uploaded_files WHERE target_id = ? AND target_type IN (\'project_attachment\', \'project_screenshot\')', [projectId]);
    await database.query('DELETE FROM projects WHERE id = ?', [projectId]);
}

async function incrementProjectViewCount(projectId) {
    const database = getPool();
    await database.query('UPDATE projects SET view_count = view_count + 1 WHERE id = ?', [projectId]);
}

async function incrementProjectDownloadCount(projectId) {
    const database = getPool();
    await database.query('UPDATE projects SET download_count = download_count + 1 WHERE id = ?', [projectId]);
}

async function refreshProjectEngagementCounts(projectId) {
    const database = getPool();
    const [likeRows] = await database.query('SELECT COUNT(*) AS count FROM project_likes WHERE project_id = ?', [projectId]);
    const [commentRows] = await database.query('SELECT COUNT(*) AS count FROM comments WHERE project_id = ? AND is_hidden = 0', [projectId]);
    await database.query(
        `
            UPDATE projects
            SET like_count = ?,
                comment_count = ?
            WHERE id = ?
        `,
        [Number(likeRows[0].count) || 0, Number(commentRows[0].count) || 0, projectId]
    );
}

async function toggleProjectLike(projectId, userDbId) {
    const database = getPool();
    const [rows] = await database.query(
        'SELECT 1 FROM project_likes WHERE project_id = ? AND user_id = ? LIMIT 1',
        [projectId, userDbId]
    );

    let liked;
    if (rows[0]) {
        await database.query('DELETE FROM project_likes WHERE project_id = ? AND user_id = ?', [projectId, userDbId]);
        liked = false;
    } else {
        await database.query('INSERT INTO project_likes (project_id, user_id) VALUES (?, ?)', [projectId, userDbId]);
        liked = true;
    }

    await refreshProjectEngagementCounts(projectId);
    return liked;
}

async function userHasLikedProject(projectId, userDbId) {
    if (!userDbId) {
        return false;
    }

    const database = getPool();
    const [rows] = await database.query(
        'SELECT 1 FROM project_likes WHERE project_id = ? AND user_id = ? LIMIT 1',
        [projectId, userDbId]
    );
    return Boolean(rows[0]);
}

async function createComment({ projectId, authorUserId, content }) {
    const database = getPool();
    const commentId = crypto.randomUUID();
    await database.query(
        `
            INSERT INTO comments (id, project_id, author_user_id, content_encrypted)
            VALUES (?, ?, ?, ?)
        `,
        [commentId, projectId, authorUserId, encryptText(content)]
    );

    await refreshProjectEngagementCounts(projectId);
    return getCommentById(commentId);
}

async function getCommentById(commentId) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT comments.*,
                   users.username AS author_username,
                   users.user_id AS author_public_user_id,
                   users.avatar_media_encrypted AS author_avatar_media_encrypted
            FROM comments
            LEFT JOIN users ON users.id = comments.author_user_id
            WHERE comments.id = ?
            LIMIT 1
        `,
        [commentId]
    );

    return rows[0] ? mapCommentRow(rows[0]) : null;
}

async function getCommentsForProject(projectId, { includeHidden = false } = {}) {
    const database = getPool();
    const condition = includeHidden ? '' : 'AND comments.is_hidden = 0';
    const [rows] = await database.query(
        `
            SELECT comments.*,
                   users.username AS author_username,
                   users.user_id AS author_public_user_id,
                   users.avatar_media_encrypted AS author_avatar_media_encrypted
            FROM comments
            LEFT JOIN users ON users.id = comments.author_user_id
            WHERE comments.project_id = ?
            ${condition}
            ORDER BY comments.created_at ASC
        `,
        [projectId]
    );

    return rows.map(mapCommentRow);
}

async function deleteComment(commentId) {
    const database = getPool();
    const comment = await getCommentById(commentId);
    if (!comment) {
        return false;
    }

    await database.query('DELETE FROM comments WHERE id = ?', [commentId]);
    await refreshProjectEngagementCounts(comment.projectId);
    return true;
}

async function setCommentHidden(commentId, hidden) {
    const database = getPool();
    await database.query('UPDATE comments SET is_hidden = ? WHERE id = ?', [hidden ? 1 : 0, commentId]);
    const comment = await getCommentById(commentId);
    if (comment) {
        await refreshProjectEngagementCounts(comment.projectId);
    }
    return comment;
}

async function createReport({ reporterUserId, targetType, targetId, reason, details }) {
    const database = getPool();
    const reportId = crypto.randomUUID();
    await database.query(
        `
            INSERT INTO reports (
                id,
                reporter_user_id,
                target_type,
                target_id,
                reason,
                details_encrypted
            ) VALUES (?, ?, ?, ?, ?, ?)
        `,
        [reportId, reporterUserId, targetType, targetId, reason, encryptText(details)]
    );

    return getReportById(reportId);
}

async function getReportById(reportId) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT reports.*,
                   reporter.username AS reporter_username,
                   reporter.user_id AS reporter_public_user_id,
                   resolver.username AS resolved_by_username,
                   resolver.user_id AS resolved_by_public_user_id
            FROM reports
            LEFT JOIN users reporter ON reporter.id = reports.reporter_user_id
            LEFT JOIN users resolver ON resolver.id = reports.resolved_by_user_id
            WHERE reports.id = ?
            LIMIT 1
        `,
        [reportId]
    );

    return rows[0] ? mapReportRow(rows[0]) : null;
}

async function getReports() {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT reports.*,
                   reporter.username AS reporter_username,
                   reporter.user_id AS reporter_public_user_id,
                   resolver.username AS resolved_by_username,
                   resolver.user_id AS resolved_by_public_user_id
            FROM reports
            LEFT JOIN users reporter ON reporter.id = reports.reporter_user_id
            LEFT JOIN users resolver ON resolver.id = reports.resolved_by_user_id
            ORDER BY FIELD(reports.status, 'open', 'reviewing', 'actioned', 'dismissed'), reports.created_at DESC
        `
    );

    return rows.map(mapReportRow);
}

async function updateReport(reportId, { status, adminNote, resolvedByUserId }) {
    const database = getPool();
    await database.query(
        `
            UPDATE reports
            SET status = ?,
                admin_note_encrypted = ?,
                resolved_by_user_id = ?,
                resolved_at = ?
            WHERE id = ?
        `,
        [status, encryptText(adminNote), resolvedByUserId || null, status === 'open' ? null : new Date(), reportId]
    );

    return getReportById(reportId);
}

async function clearAllReports() {
    const database = getPool();
    const [result] = await database.query('DELETE FROM reports');
    return Number(result.affectedRows) || 0;
}

async function followUser(followerUserId, followedUserId) {
    const database = getPool();
    await database.query(
        'INSERT IGNORE INTO user_follows (follower_user_id, followed_user_id) VALUES (?, ?)',
        [followerUserId, followedUserId]
    );
}

async function unfollowUser(followerUserId, followedUserId) {
    const database = getPool();
    await database.query(
        'DELETE FROM user_follows WHERE follower_user_id = ? AND followed_user_id = ?',
        [followerUserId, followedUserId]
    );
}

async function isFollowingUser(followerUserId, followedUserId) {
    if (!followerUserId || !followedUserId) {
        return false;
    }

    const database = getPool();
    const [rows] = await database.query(
        'SELECT 1 FROM user_follows WHERE follower_user_id = ? AND followed_user_id = ? LIMIT 1',
        [followerUserId, followedUserId]
    );
    return Boolean(rows[0]);
}

async function getFollowedUserIds(followerUserId) {
    const database = getPool();
    const [rows] = await database.query(
        'SELECT followed_user_id FROM user_follows WHERE follower_user_id = ?',
        [followerUserId]
    );
    return rows.map((row) => Number(row.followed_user_id)).filter(Boolean);
}

async function getVisibleProjectsForOwner(ownerUserId, viewerUserDbId = null) {
    if (viewerUserDbId && viewerUserDbId === ownerUserId) {
        return getProjects({ ownerUserId });
    }

    const projects = await getProjects({ ownerUserId });
    return projects.filter((project) => project.visibility === 'public');
}

async function getPublicUserProfile(userPublicId, viewerUserDbId = null) {
    const user = await findUserByPublicId(userPublicId);
    if (!user) {
        return null;
    }

    const projects = await getVisibleProjectsForOwner(user.id, viewerUserDbId);
    const isFollowing = viewerUserDbId ? await isFollowingUser(viewerUserDbId, user.id) : false;
    return {
        user,
        projects,
        isFollowing
    };
}

async function getLatestCommentTimestampForUser(userDbId) {
    const database = getPool();
    const [rows] = await database.query(
        'SELECT created_at FROM comments WHERE author_user_id = ? ORDER BY created_at DESC LIMIT 1',
        [userDbId]
    );
    return rows[0] ? rows[0].created_at : null;
}

async function getLatestProjectTimestampForUser(userDbId) {
    const database = getPool();
    const [rows] = await database.query(
        'SELECT created_at FROM projects WHERE owner_user_id = ? ORDER BY created_at DESC LIMIT 1',
        [userDbId]
    );
    return rows[0] ? rows[0].created_at : null;
}

async function upsertUploadedFileRecord({ storedName, ownerUserId, targetType, targetId, originalName, mimeType, size }) {
    const database = getPool();
    await database.query(
        `
            INSERT INTO uploaded_files (
                stored_name,
                owner_user_id,
                target_type,
                target_id,
                original_name_encrypted,
                mime_type,
                size
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                owner_user_id = VALUES(owner_user_id),
                target_type = VALUES(target_type),
                target_id = VALUES(target_id),
                original_name_encrypted = VALUES(original_name_encrypted),
                mime_type = VALUES(mime_type),
                size = VALUES(size)
        `,
        [storedName, ownerUserId, targetType, targetId, encryptText(originalName), mimeType, Number(size) || 0]
    );
}

async function deleteUploadedFileRecords(storedNames = []) {
    const names = [...new Set(storedNames.map((entry) => String(entry || '').trim()).filter(Boolean))];
    if (!names.length) {
        return;
    }

    const database = getPool();
    await database.query(
        `DELETE FROM uploaded_files WHERE stored_name IN (${names.map(() => '?').join(', ')})`,
        names
    );
}

async function getUploadedFileByStoredName(storedName) {
    const database = getPool();
    const [rows] = await database.query(
        'SELECT * FROM uploaded_files WHERE stored_name = ? LIMIT 1',
        [storedName]
    );

    return rows[0] ? mapUploadedFileRow(rows[0]) : null;
}

async function getLatestUploads(limit = 8) {
    const database = getPool();
    const [rows] = await database.query(
        `
            SELECT uploaded_files.*, users.username AS owner_username, users.user_id AS owner_public_user_id, projects.title_encrypted
            FROM uploaded_files
            LEFT JOIN users ON users.id = uploaded_files.owner_user_id
            LEFT JOIN projects ON projects.id = uploaded_files.target_id AND uploaded_files.target_type IN ('project_attachment', 'project_screenshot')
            ORDER BY uploaded_files.created_at DESC
            LIMIT ?
        `,
        [Math.max(1, Number(limit) || 8)]
    );

    return rows.map((row) => ({
        ...mapUploadedFileRow(row),
        owner: row.owner_username || 'Deleted User',
        ownerUserId: row.owner_public_user_id || null,
        projectId: row.target_type.startsWith('project_') ? row.target_id : null,
        projectTitle: decryptText(row.title_encrypted)
    }));
}

async function getStorageDashboard() {
    const database = getPool();
    const [rows] = await database.query(`
        SELECT users.id, users.user_id, users.username,
               COALESCE(SUM(uploaded_files.size), 0) AS storage_bytes,
               COUNT(uploaded_files.stored_name) AS file_count
        FROM users
        LEFT JOIN uploaded_files ON uploaded_files.owner_user_id = users.id
        GROUP BY users.id, users.user_id, users.username
        ORDER BY storage_bytes DESC, file_count DESC, users.username ASC
    `);

    const [siteRows] = await database.query(`
        SELECT
            COALESCE(SUM(size), 0) AS total_bytes,
            COUNT(*) AS total_files
        FROM uploaded_files
    `);

    return {
        users: rows.map((row) => ({
            userId: row.user_id,
            username: row.username,
            storageBytes: Number(row.storage_bytes) || 0,
            fileCount: Number(row.file_count) || 0
        })),
        totalBytes: Number(siteRows[0].total_bytes) || 0,
        totalFiles: Number(siteRows[0].total_files) || 0
    };
}

async function getSiteSettings() {
    const database = getPool();
    const [rows] = await database.query('SELECT * FROM site_settings WHERE id = 1 LIMIT 1');
    return mapSiteSettingsRow(rows[0]);
}

async function updateSiteSettings(updates) {
    const database = getPool();
    const currentSettings = await getSiteSettings();
    const nextSettings = normalizeSiteSettingsInput(currentSettings, updates);

    await database.query(
        `
            UPDATE site_settings
            SET registrations_enabled = ?,
                login_enabled = ?,
                uploads_enabled = ?,
                project_limit_enabled = ?,
                max_projects_per_user = ?,
                upload_size_limit_enabled = ?,
                max_upload_size_mb = ?,
                invite_only_enabled = ?,
                approval_required = ?,
                new_account_restrictions_enabled = ?,
                new_account_restriction_hours = ?,
                announcement_enabled = ?,
                announcement_text_encrypted = ?,
                announcement_link = ?,
                trust_level_enabled = ?,
                low_trust_age_hours = ?,
                low_trust_comment_cooldown_seconds = ?,
                low_trust_project_cooldown_minutes = ?,
                word_blacklist_encrypted = ?
            WHERE id = 1
        `,
        [
            nextSettings.registrationsEnabled ? 1 : 0,
            nextSettings.loginEnabled ? 1 : 0,
            nextSettings.uploadsEnabled ? 1 : 0,
            nextSettings.projectLimitEnabled ? 1 : 0,
            nextSettings.maxProjectsPerUser,
            nextSettings.uploadSizeLimitEnabled ? 1 : 0,
            nextSettings.maxUploadSizeMb,
            nextSettings.inviteOnlyEnabled ? 1 : 0,
            nextSettings.approvalRequired ? 1 : 0,
            nextSettings.newAccountRestrictionsEnabled ? 1 : 0,
            nextSettings.newAccountRestrictionHours,
            nextSettings.announcementEnabled ? 1 : 0,
            encryptText(nextSettings.announcementText),
            nextSettings.announcementLink,
            nextSettings.trustLevelEnabled ? 1 : 0,
            nextSettings.lowTrustAgeHours,
            nextSettings.lowTrustCommentCooldownSeconds,
            nextSettings.lowTrustProjectCooldownMinutes,
            encryptJson(nextSettings.wordBlacklist)
        ]
    );

    return getSiteSettings();
}

async function getSiteStats() {
    const database = getPool();
    const [rows] = await database.query(`
        SELECT
            (SELECT COUNT(*) FROM users) AS total_users,
            (SELECT COUNT(*) FROM projects WHERE visibility = 'public') AS total_projects,
            (SELECT COALESCE(SUM(download_count), 0) FROM projects) AS total_downloads,
            (SELECT COALESCE(SUM(view_count), 0) FROM projects) AS total_views
    `);

    return {
        totalUsers: Number(rows[0].total_users) || 0,
        totalProjects: Number(rows[0].total_projects) || 0,
        totalDownloads: Number(rows[0].total_downloads) || 0,
        totalViews: Number(rows[0].total_views) || 0
    };
}

module.exports = {
    buildFileUrl,
    buildMediaUrl,
    clearAllReports,
    countAdmins,
    countProjectsForUser,
    createAuditLog,
    createComment,
    createEmailVerificationToken,
    createInviteCode,
    createNotification,
    createProject,
    createReport,
    createSession,
    createUser,
    deleteComment,
    deleteProject,
    deleteSession,
    deleteSessionsForUser,
    deleteUploadedFileRecords,
    deleteUserByPublicId,
    disableUserTwoFactor,
    enableUserTwoFactor,
    findUserById,
    findUserByEmail,
    findUserByEmailVerificationToken,
    findUserByPublicId,
    findUserBySessionToken,
    findUsersByUsernames,
    findUserByUsername,
    followUser,
    getAllUsers,
    getAuditLogs,
    getCommentById,
    getFollowedUserIds,
    getCommentsForProject,
    getLatestCommentTimestampForUser,
    getLatestProjectTimestampForUser,
    getLatestUploads,
    getNotificationsForUser,
    getProjectById,
    getProjects,
    getProjectsForUser,
    getPublicUserProfile,
    getReportById,
    getReports,
    getSiteSettings,
    getSiteStats,
    getStorageDashboard,
    getUploadedFileByStoredName,
    getInviteCode,
    hashPassword,
    incrementProjectDownloadCount,
    incrementProjectViewCount,
    initializeDatabase,
    isFollowingUser,
    listInviteCodes,
    markUserEmailVerified,
    markAllNotificationsRead,
    normalizeChangelog,
    normalizeDevlogs,
    normalizeFileEntries,
    normalizeKnownBugs,
    normalizeExternalLinks,
    normalizeProfileMedia,
    normalizeTag,
    normalizeTags,
    refreshProjectEngagementCounts,
    replaceUserTwoFactorBackupCodes,
    setCommentHidden,
    setUserApprovalStatus,
    setUserBanStatus,
    setUserForcePasswordReset,
    setUserRole,
    storePendingTwoFactorSecret,
    toggleProjectLike,
    unfollowUser,
    updateProject,
    updateReport,
    updateSiteSettings,
    updateUserPassword,
    updateUserProfile,
    upsertUploadedFileRecord,
    userHasLikedProject,
    verifyPassword,
    consumeInviteCode,
    revokeInviteCode
};
