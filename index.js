require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const {
    clearAllReports,
    clearLoginAttemptState,
    countAdmins,
    countProjectsForUser,
    createAuditLog,
    createComment,
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
    deleteUserByPublicId,
    disableUserTwoFactor,
    enableUserTwoFactor,
    followUser,
    findUserByEmail,
    findUserById,
    findUserByPublicId,
    findUserBySessionToken,
    findUsersByUsernames,
    findUserByUsername,
    getAllUsers,
    getAuditLogs,
    getCommentById,
    getCommentsForProject,
    getFollowedUserIds,
    getLatestCommentTimestampForUser,
    getLoginAttemptState,
    getLatestProjectTimestampForUser,
    getLatestUploads,
    getNotificationsForUser,
    getProjectById,
    getProjects,
    getProjectsForUser,
    getPublicUserProfile,
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
    markAllNotificationsRead,
    recordFailedLoginAttempt,
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
    updateSiteSettings,
    updateReport,
    updateUserPassword,
    updateUserProfile,
    userHasLikedProject,
    verifyPassword,
    consumeInviteCode,
    revokeInviteCode
} = require('./db');

const app = express();
const port = Number(process.env.PORT || 3000);
const dbInitRetries = Number(process.env.DB_INIT_RETRIES || 120);
const dbInitDelayMs = Number(process.env.DB_INIT_DELAY_MS || 5000);
const filesDirectory = path.join(__dirname, 'files');
const absoluteUploadLimitMb = Math.max(1, Number(process.env.HARD_UPLOAD_SIZE_MB || 250));
const absoluteUploadLimitBytes = absoluteUploadLimitMb * 1024 * 1024;
const encryptedFileMagic = Buffer.from('QKY1');
const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const backupCodeAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const recaptchaSiteKey = String(process.env.RECAPTCHA_SITE_KEY || '').trim();
const recaptchaSecretKey = String(process.env.RECAPTCHA_SECRET_KEY || '').trim();
const disposableEmailDomains = new Set([
    '10minutemail.com',
    '10minutemail.net',
    'dispostable.com',
    'emailondeck.com',
    'fakeinbox.com',
    'getairmail.com',
    'getnada.com',
    'guerrillamail.com',
    'maildrop.cc',
    'mailinator.com',
    'mintemail.com',
    'sharklasers.com',
    'temp-mail.org',
    'tempail.com',
    'tempmail.com',
    'tempmail.dev',
    'tempmailo.com',
    'throwawaymail.com',
    'trashmail.com',
    'yopmail.com'
]);
const allowedUploadExtensions = new Set([
    '.apk', '.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz',
    '.pdf', '.txt', '.md', '.csv', '.json',
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico',
    '.mp3', '.wav', '.ogg', '.mp4', '.mov', '.webm', '.mkv', '.avi',
    '.apk', '.exe', '.msi', '.dmg', '.iso', '.jar'
]);

app.disable('x-powered-by');
app.set('trust proxy', parseTrustProxy(process.env.TRUST_PROXY));

fs.mkdirSync(filesDirectory, { recursive: true });

const uploadStorage = multer.memoryStorage();

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            objectSrc: ["'none'"],
            imgSrc: ["'self'", 'data:', 'https://www.gstatic.com', 'https://www.google.com'],
            scriptSrc: ["'self'", 'https://www.google.com', 'https://www.gstatic.com'],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", 'https://www.google.com'],
            frameSrc: ["'self'", 'https://www.google.com', 'https://recaptcha.google.com']
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: true, limit: '32kb' }));

const apiRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.API_RATE_LIMIT || 300),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please slow down and try again shortly.' },
    handler: rateLimitHandler
});

const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.AUTH_RATE_LIMIT || 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login or registration attempts. Please wait before trying again.' },
    handler: rateLimitHandler
});

const loginMaxFailedAttempts = Math.max(1, Number(process.env.LOGIN_MAX_FAILED_ATTEMPTS || 4));
const loginLockoutMinutes = Math.max(1, Number(process.env.LOGIN_LOCKOUT_MINUTES || 10));

const projectMutationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.PROJECT_MUTATION_RATE_LIMIT || 30),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many project changes in a short time. Please wait a bit and try again.' },
    handler: rateLimitHandler
});

app.use('/api', apiRateLimiter);

function parseTrustProxy(value) {
    if (value == null || value === '') {
        return 1;
    }

    if (value === 'true') {
        return true;
    }

    if (value === 'false') {
        return false;
    }

    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : value;
}

function rateLimitHandler(_req, res, _next, options) {
    return res.status(options.statusCode).json(options.message);
}

function sendLoginLockoutResponse(res, lockedUntil) {
    const lockedUntilDate = lockedUntil ? new Date(lockedUntil) : null;
    const retryAfterSeconds = lockedUntilDate
        ? Math.max(1, Math.ceil((lockedUntilDate.getTime() - Date.now()) / 1000))
        : loginLockoutMinutes * 60;
    const retryAfterMinutes = Math.max(1, Math.ceil(retryAfterSeconds / 60));

    res.setHeader('Retry-After', String(retryAfterSeconds));
    return res.status(429).json({
        error: `Too many failed login attempts from this IP for that username. Try again in ${retryAfterMinutes} minute${retryAfterMinutes === 1 ? '' : 's'}.`,
        retryAfterSeconds,
        lockedUntil: lockedUntilDate ? lockedUntilDate.toISOString() : null
    });
}

function parseCookies(cookieHeader = '') {
    return cookieHeader
        .split(';')
        .map((chunk) => chunk.trim())
        .filter(Boolean)
        .reduce((accumulator, pair) => {
            const index = pair.indexOf('=');
            if (index === -1) {
                return accumulator;
            }

            const key = pair.slice(0, index);
            const value = pair.slice(index + 1);
            accumulator[key] = decodeURIComponent(value);
            return accumulator;
        }, {});
}

function shouldUseSecureCookies() {
    const configuredValue = process.env.COOKIE_SECURE;
    if (configuredValue != null && configuredValue !== '') {
        return normalizeBoolean(configuredValue);
    }

    return process.env.NODE_ENV === 'production';
}

function buildSessionCookie(token) {
    const parts = [
        `session=${encodeURIComponent(token)}`,
        'HttpOnly',
        'Path=/',
        'SameSite=Strict',
        `Max-Age=${60 * 60 * 24 * 7}`
    ];

    if (shouldUseSecureCookies()) {
        parts.push('Secure');
    }

    return parts.join('; ');
}

function clearSessionCookie() {
    const parts = ['session=;', 'HttpOnly', 'Path=/', 'SameSite=Strict', 'Max-Age=0'];

    if (shouldUseSecureCookies()) {
        parts.push('Secure');
    }

    return parts.join('; ');
}

function normalizeEmailAddress(value) {
    return String(value || '').trim().toLowerCase();
}

function isRecaptchaEnabled() {
    return Boolean(recaptchaSiteKey && recaptchaSecretKey);
}

function toClientSettings(settings) {
    return {
        registrationsEnabled: Boolean(settings.registrationsEnabled),
        loginEnabled: Boolean(settings.loginEnabled),
        uploadsEnabled: Boolean(settings.uploadsEnabled),
        projectLimitEnabled: Boolean(settings.projectLimitEnabled),
        maxProjectsPerUser: Number(settings.maxProjectsPerUser) || 10,
        uploadSizeLimitEnabled: Boolean(settings.uploadSizeLimitEnabled),
        maxUploadSizeMb: Number(settings.maxUploadSizeMb) || 25,
        inviteOnlyEnabled: Boolean(settings.inviteOnlyEnabled),
        approvalRequired: Boolean(settings.approvalRequired),
        newAccountRestrictionsEnabled: Boolean(settings.newAccountRestrictionsEnabled),
        newAccountRestrictionHours: Number(settings.newAccountRestrictionHours) || 24,
        announcementEnabled: Boolean(settings.announcementEnabled),
        announcementText: String(settings.announcementText || ''),
        announcementLink: String(settings.announcementLink || ''),
        trustLevelEnabled: settings.trustLevelEnabled == null ? true : Boolean(settings.trustLevelEnabled),
        lowTrustAgeHours: Number(settings.lowTrustAgeHours) || 72,
        lowTrustCommentCooldownSeconds: Number(settings.lowTrustCommentCooldownSeconds) || 45,
        lowTrustProjectCooldownMinutes: Number(settings.lowTrustProjectCooldownMinutes) || 30,
        recaptchaEnabled: isRecaptchaEnabled(),
        recaptchaSiteKey: isRecaptchaEnabled() ? recaptchaSiteKey : ''
    };
}

function toAdminSettings(settings) {
    return {
        ...toClientSettings(settings),
        wordBlacklist: Array.isArray(settings.wordBlacklist) ? settings.wordBlacklist : []
    };
}

function normalizeBoolean(value) {
    return value === true
        || value === 'true'
        || value === '1'
        || value === 1
        || value === 'on';
}

function normalizePositiveInteger(value, fallback) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed < 1) {
        return fallback;
    }

    return Math.floor(parsed);
}

function isDisposableEmail(email) {
    const domain = normalizeEmailAddress(email).split('@')[1] || '';
    const extraDomains = String(process.env.DISPOSABLE_EMAIL_DOMAINS || '')
        .split(',')
        .map((entry) => entry.trim().toLowerCase())
        .filter(Boolean);
    return disposableEmailDomains.has(domain) || extraDomains.includes(domain);
}

async function verifyRecaptchaToken(token, remoteIp) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
        const params = new URLSearchParams({
            secret: recaptchaSecretKey,
            response: String(token || '').trim()
        });

        if (remoteIp) {
            params.set('remoteip', remoteIp);
        }

        const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params,
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error('Captcha verification service is unavailable right now.');
        }

        return response.json();
    } finally {
        clearTimeout(timeoutId);
    }
}

function normalizeProjectPayload(body) {
    return {
        title: String(body.title || '').trim(),
        summary: String(body.summary || '').trim(),
        description: String(body.description || '').trim(),
        type: String(body.type || '').trim() || 'Project',
        status: String(body.status || '').trim() || 'Draft',
        visibility: String(body.visibility || '').trim().toLowerCase() || 'public',
        tags: String(body.tags || '').trim(),
        changelog: String(body.changelog || '').trim(),
        devlogs: String(body.devlogs || '').trim(),
        knownBugs: String(body.knownBugs || '').trim(),
        externalLinks: String(body.externalLinks || '').trim(),
        owners: String(body.owners || '').trim(),
        featured: normalizeBoolean(body.featured)
    };
}

function validateProjectPayload(payload) {
    if (!payload.title) {
        return 'Project name is required.';
    }

    if (!payload.description) {
        return 'Project description is required.';
    }

    return null;
}

function buildUserBadges(user) {
    const badges = [];
    if (!user) {
        return badges;
    }

    if (user.role === 'admin') {
        badges.push({ id: 'staff', label: 'Staff' });
    }
    if (user.twoFactorEnabled) {
        badges.push({ id: 'secure', label: '2FA' });
    }
    if ((Number(user.projectCount) || 0) >= 1) {
        badges.push({ id: 'builder', label: 'Builder' });
    }
    if ((Number(user.projectCount) || 0) >= 5) {
        badges.push({ id: 'creator', label: 'Creator' });
    }
    if ((Number(user.followerCount) || 0) >= 10) {
        badges.push({ id: 'followed', label: 'Followed' });
    }
    if ((Number(user.followerCount) || 0) >= 50) {
        badges.push({ id: 'popular', label: 'Popular' });
    }

    return badges.slice(0, 4);
}

function parseRemovedFiles(value) {
    if (!value) {
        return [];
    }

    if (Array.isArray(value)) {
        return value.map((entry) => String(entry || '').trim()).filter(Boolean);
    }

    if (typeof value === 'string') {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed)
                ? parsed.map((entry) => String(entry || '').trim()).filter(Boolean)
                : [];
        } catch (error) {
            return value
                .split(',')
                .map((entry) => entry.trim())
                .filter(Boolean);
        }
    }

    return [];
}

function normalizeReportReason(value) {
    const allowedReasons = new Set([
        'spam',
        'abuse',
        'copyright',
        'malware',
        'nsfw',
        'harassment',
        'other'
    ]);
    const normalized = String(value || '').trim().toLowerCase();
    return allowedReasons.has(normalized) ? normalized : 'other';
}

function sanitizeProjectForClient(project) {
    if (!project) {
        return null;
    }

    return {
        id: project.id,
        title: project.title,
        summary: project.summary,
        description: project.description,
        type: project.type,
        status: project.status,
        visibility: project.visibility,
        featured: Boolean(project.featured),
        tags: Array.isArray(project.tags) ? project.tags : [],
        screenshots: Array.isArray(project.screenshots) ? project.screenshots : [],
        downloadables: Array.isArray(project.downloadables) ? project.downloadables : [],
        changelog: Array.isArray(project.changelog) ? project.changelog : [],
        devlogs: Array.isArray(project.devlogs) ? project.devlogs : [],
        knownBugs: Array.isArray(project.knownBugs) ? project.knownBugs : [],
        externalLinks: Array.isArray(project.externalLinks) ? project.externalLinks : [],
        viewCount: Number(project.viewCount) || 0,
        downloadCount: Number(project.downloadCount) || 0,
        likeCount: Number(project.likeCount) || 0,
        commentCount: Number(project.commentCount) || 0,
        owner: project.owner || 'Deleted User',
        ownerUserId: project.ownerUserId || null,
        ownerAvatarMedia: project.ownerAvatarMedia || null,
        owners: Array.isArray(project.owners) ? project.owners : [],
        createdAt: project.createdAt,
        updatedAt: project.updatedAt
    };
}

function sanitizeCurrentUser(user, settings = null) {
    if (!user) {
        return null;
    }

    return {
        userId: user.userId,
        username: user.username,
        email: user.email,
        role: user.role,
        isApproved: user.isApproved,
        isBanned: user.isBanned,
        banReason: user.banReason || '',
        banExpiresAt: user.banExpiresAt || null,
        twoFactorEnabled: user.twoFactorEnabled,
        forcePasswordReset: user.forcePasswordReset,
        bio: user.bio || '',
        avatarMedia: user.avatarMedia || null,
        bannerMedia: user.bannerMedia || null,
        followerCount: Number(user.followerCount) || 0,
        followingCount: Number(user.followingCount) || 0,
        projectCount: Number(user.projectCount) || 0,
        badges: buildUserBadges(user),
        trustLevel: settings ? getUserTrustLevel(user, settings) : 'trusted',
        createdAt: user.createdAt
    };
}

function isNewAccountRestricted(user, settings) {
    if (!user || user.role === 'admin' || !settings.newAccountRestrictionsEnabled) {
        return false;
    }

    const createdAt = new Date(user.createdAt);
    if (!Number.isFinite(createdAt.getTime())) {
        return false;
    }

    const restrictionMs = (Number(settings.newAccountRestrictionHours) || 24) * 60 * 60 * 1000;
    return Date.now() - createdAt.getTime() < restrictionMs;
}

function getNewAccountRestrictionMessage(settings) {
    const hours = Number(settings.newAccountRestrictionHours) || 24;
    return `New accounts need to age for ${hours} hour${hours === 1 ? '' : 's'} before using this feature.`;
}

function getBanMessage(user) {
    if (!user || !user.isBanned) {
        return 'This account is banned from using the site.';
    }

    const details = [];
    const reason = String(user.banReason || '').trim();
    if (reason) {
        details.push(`Reason: ${reason}`);
    }

    if (user.banExpiresAt) {
        details.push(`Ban ends at ${new Date(user.banExpiresAt).toLocaleString()}.`);
    }

    return details.length
        ? `This account is banned from using the site. ${details.join(' ')}`
        : 'This account is banned from using the site.';
}

function isAllowedDuringBanRestriction(requestPath = '') {
    return requestPath === '/api/me'
        || requestPath === '/api/logout'
        || requestPath === '/api/profile/password';
}

function getBlockedWords(settings) {
    return (Array.isArray(settings?.wordBlacklist) ? settings.wordBlacklist : [])
        .map((entry) => String(entry || '').trim().toLowerCase())
        .filter(Boolean);
}

function findBlockedWord(settings, ...parts) {
    const blockedWords = getBlockedWords(settings);
    if (!blockedWords.length) {
        return null;
    }

    const haystack = parts
        .flat()
        .map((entry) => String(entry || '').toLowerCase())
        .join('\n');

    return blockedWords.find((word) => haystack.includes(word)) || null;
}

function getUserTrustLevel(user, settings) {
    if (!user) {
        return 'guest';
    }

    if (user.role === 'admin' || !settings?.trustLevelEnabled) {
        return 'trusted';
    }

    const createdAt = new Date(user.createdAt);
    const accountAgeHours = Number.isFinite(createdAt.getTime())
        ? (Date.now() - createdAt.getTime()) / (1000 * 60 * 60)
        : Number.MAX_SAFE_INTEGER;
    const thresholdHours = Number(settings.lowTrustAgeHours) || 72;

    if (
        accountAgeHours >= thresholdHours
        || Boolean(user.twoFactorEnabled)
        || (Number(user.projectCount) || 0) >= 2
        || (Number(user.followerCount) || 0) >= 5
    ) {
        return 'trusted';
    }

    return 'low';
}

function getTrustCooldownMessage(kind, amount) {
    if (kind === 'comment') {
        return `Low-trust accounts need to wait ${amount} second${amount === 1 ? '' : 's'} between comments.`;
    }

    return `Low-trust accounts need to wait ${amount} minute${amount === 1 ? '' : 's'} between new projects.`;
}

async function enforceLowTrustCooldown(user, settings, kind) {
    if (!user || getUserTrustLevel(user, settings) !== 'low') {
        return null;
    }

    if (kind === 'comment') {
        const cooldownSeconds = Number(settings.lowTrustCommentCooldownSeconds) || 0;
        if (cooldownSeconds <= 0) {
            return null;
        }

        const latestCommentAt = await getLatestCommentTimestampForUser(user.id);
        if (!latestCommentAt) {
            return null;
        }

        const elapsedSeconds = (Date.now() - new Date(latestCommentAt).getTime()) / 1000;
        if (elapsedSeconds < cooldownSeconds) {
            return getTrustCooldownMessage('comment', cooldownSeconds);
        }
        return null;
    }

    const cooldownMinutes = Number(settings.lowTrustProjectCooldownMinutes) || 0;
    if (cooldownMinutes <= 0) {
        return null;
    }

    const latestProjectAt = await getLatestProjectTimestampForUser(user.id);
    if (!latestProjectAt) {
        return null;
    }

    const elapsedMinutes = (Date.now() - new Date(latestProjectAt).getTime()) / (1000 * 60);
    if (elapsedMinutes < cooldownMinutes) {
        return getTrustCooldownMessage('project', cooldownMinutes);
    }

    return null;
}

async function resolveProjectCoOwners(rawOwners, currentUser) {
    const usernames = [...new Set(
        String(rawOwners || '')
            .split(/[\n,]/)
            .map((entry) => entry.trim())
            .filter(Boolean)
    )].slice(0, 10);

    if (!usernames.length) {
        return { users: [], userIds: [] };
    }

    const users = await findUsersByUsernames(usernames);
    const usersByUsername = new Map(users.map((entry) => [entry.username.toLowerCase(), entry]));
    const missing = usernames.filter((username) => !usersByUsername.has(username.toLowerCase()));
    if (missing.length) {
        const label = missing.length === 1 ? 'username' : 'usernames';
        throw new Error(`Unknown collaborator ${label}: ${missing.join(', ')}`);
    }

    const uniqueUsers = usernames
        .map((username) => usersByUsername.get(username.toLowerCase()))
        .filter((entry) => entry && entry.id !== currentUser.id);

    return {
        users: uniqueUsers,
        userIds: uniqueUsers.map((entry) => entry.id)
    };
}

function sanitizePublicUser(user, settings = null) {
    if (!user) {
        return null;
    }

    return {
        userId: user.userId,
        username: user.username,
        role: user.role,
        bio: user.bio || '',
        avatarMedia: user.avatarMedia || null,
        bannerMedia: user.bannerMedia || null,
        followerCount: Number(user.followerCount) || 0,
        followingCount: Number(user.followingCount) || 0,
        projectCount: Number(user.projectCount) || 0,
        badges: buildUserBadges(user),
        trustLevel: settings ? getUserTrustLevel(user, settings) : 'trusted',
        createdAt: user.createdAt
    };
}

function getUploadGroup(req, fieldName) {
    if (!req.files) {
        return [];
    }

    if (Array.isArray(req.files)) {
        return fieldName === 'projectFiles' ? req.files : [];
    }

    return Array.isArray(req.files[fieldName]) ? req.files[fieldName] : [];
}

function collectStoredEntries(...groups) {
    return groups.flat().filter(Boolean);
}

function canManageProject(project, user) {
    return Boolean(
        project
        && user
        && (
            user.role === 'admin'
            || project.ownerDbId === user.id
            || (Array.isArray(project.ownerDbIds) && project.ownerDbIds.includes(user.id))
        )
    );
}

function canViewProject(project, user) {
    if (!project) {
        return false;
    }

    if (project.visibility === 'public' || project.visibility === 'unlisted') {
        return true;
    }

    return canManageProject(project, user);
}

function isImageMimeType(mimeType) {
    return new Set([
        'image/png',
        'image/jpeg',
        'image/jpg',
        'image/gif',
        'image/webp',
        'image/bmp',
        'image/x-icon',
        'image/vnd.microsoft.icon'
    ]).has(String(mimeType || '').toLowerCase());
}

function calculateTrendingScore(project) {
    const ageHours = Math.max(1, (Date.now() - new Date(project.updatedAt || project.createdAt || Date.now()).getTime()) / (1000 * 60 * 60));
    const engagement = (Number(project.viewCount) || 0)
        + ((Number(project.downloadCount) || 0) * 6)
        + ((Number(project.likeCount) || 0) * 8)
        + ((Number(project.commentCount) || 0) * 10);

    return engagement / Math.pow(ageHours + 6, 0.55);
}

function matchesFollowedCreators(project, followedUserIds = []) {
    const followed = new Set((followedUserIds || []).map((entry) => Number(entry)).filter(Boolean));
    if (!followed.size) {
        return false;
    }

    return (Array.isArray(project.ownerDbIds) ? project.ownerDbIds : [project.ownerDbId]).some((entry) => followed.has(Number(entry)));
}

function isAllowedDuringForcedPasswordReset(requestPath = '') {
    return requestPath === '/api/me'
        || requestPath === '/api/logout'
        || requestPath === '/api/profile/password'
        || requestPath.startsWith('/api/profile/2fa');
}

function getStoredFileNames(downloadables = []) {
    return downloadables
        .filter((entry) => entry && entry.type === 'file' && entry.storedName)
        .map((entry) => path.basename(entry.storedName));
}

function getDownloadableKey(entry) {
    if (!entry) {
        return '';
    }

    return entry.storedName || entry.url || entry.name || '';
}

function sanitizeOriginalFileName(name) {
    const cleaned = path.basename(String(name || 'download'))
        .replace(/[^\w.\-() ]+/g, '_')
        .trim()
        .slice(0, 120);

    return cleaned || 'download.bin';
}

function normalizeStoredFileName(value) {
    const storedName = path.basename(String(value || '').trim());
    if (!storedName || !/^[a-z0-9._-]+$/i.test(storedName)) {
        return '';
    }

    return storedName;
}

function encryptFileBuffer(buffer) {
    const key = Buffer.from(process.env.APP_ENCRYPTION_KEY, 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([encryptedFileMagic, iv, tag, encrypted]);
}

function decryptFileBuffer(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        return Buffer.from(buffer || '');
    }

    if (buffer.length < encryptedFileMagic.length + 12 + 16) {
        return buffer;
    }

    const magic = buffer.subarray(0, encryptedFileMagic.length);
    if (!magic.equals(encryptedFileMagic)) {
        return buffer;
    }

    const ivStart = encryptedFileMagic.length;
    const tagStart = ivStart + 12;
    const payloadStart = tagStart + 16;
    const iv = buffer.subarray(ivStart, tagStart);
    const tag = buffer.subarray(tagStart, payloadStart);
    const encryptedPayload = buffer.subarray(payloadStart);
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(process.env.APP_ENCRYPTION_KEY, 'hex'), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encryptedPayload), decipher.final()]);
}

function isAllowedUpload(file) {
    const extension = path.extname(String(file.originalname || '')).toLowerCase();
    return allowedUploadExtensions.has(extension);
}

function createUploadMiddleware(user, settings) {
    const limits = {};
    const configuredLimitMb = user.role !== 'admin' && settings.uploadSizeLimitEnabled
        ? settings.maxUploadSizeMb
        : absoluteUploadLimitMb;
    const effectiveLimitBytes = Math.min(
        absoluteUploadLimitBytes,
        Math.max(1, Number(configuredLimitMb) || absoluteUploadLimitMb) * 1024 * 1024
    );

    limits.fileSize = effectiveLimitBytes;

    return multer({
        storage: uploadStorage,
        limits,
        fileFilter: (_req, file, callback) => {
            if (!isAllowedUpload(file)) {
                callback(new Error('That file type is not allowed. Upload archives, documents, media files, or app packages only.'));
                return;
            }

            callback(null, true);
        }
    }).fields([
        { name: 'projectFiles', maxCount: user.role === 'admin' ? 50 : 10 },
        { name: 'projectScreenshots', maxCount: user.role === 'admin' ? 24 : 12 },
        { name: 'avatarFile', maxCount: 1 },
        { name: 'bannerFile', maxCount: 1 }
    ]);
}

function runUploadMiddleware(req, res, user, settings) {
    return new Promise((resolve, reject) => {
        createUploadMiddleware(user, settings)(req, res, (error) => {
            if (error) {
                reject(error);
                return;
            }

            resolve();
        });
    });
}

async function persistUploadedFiles(files = []) {
    const savedRecords = [];

    try {
        for (const file of files) {
            const originalName = sanitizeOriginalFileName(file.originalname || 'download.bin');
            const storedName = `${crypto.randomUUID()}.bin`;
            const encryptedPayload = encryptFileBuffer(file.buffer);
            await fs.promises.writeFile(path.join(filesDirectory, storedName), encryptedPayload, { mode: 0o600 });
            savedRecords.push({
                type: 'file',
                name: originalName,
                storedName,
                url: `/files/${encodeURIComponent(storedName)}?name=${encodeURIComponent(originalName)}`,
                size: Number(file.size) || 0,
                mimeType: file.mimetype || 'application/octet-stream'
            });
        }

        return savedRecords;
    } catch (error) {
        await removeStoredFiles(savedRecords);
        throw error;
    }
}

async function removeStoredFileNames(storedNames = []) {
    const uniqueNames = [...new Set(storedNames.map((entry) => path.basename(String(entry || ''))).filter(Boolean))];
    await Promise.allSettled(
        uniqueNames.map(async (storedName) => {
            try {
                await fs.promises.unlink(path.join(filesDirectory, storedName));
            } catch (error) {
                if (error.code !== 'ENOENT') {
                    throw error;
                }
            }
        })
    );
}

async function removeStoredFiles(downloadables = []) {
    await removeStoredFileNames(getStoredFileNames(downloadables));
}

async function removeProjectStoredFiles(project) {
    if (!project) {
        return;
    }

    await removeStoredFiles([
        ...(project.downloadables || []),
        ...(project.screenshots || [])
    ]);
}

function sendApiError(res, error, status = 500) {
    if (error && error.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'That value already exists.' });
    }

    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ error: `One of the uploaded files is larger than the current hard limit of ${absoluteUploadLimitMb} MB.` });
        }

        return res.status(400).json({ error: error.message || 'The uploaded files could not be processed.' });
    }

    if (error && error.message) {
        return res.status(error.statusCode || status).json({ error: error.message });
    }

    return res.status(status).json({ error: 'Something went wrong.' });
}

function withApiError(handler) {
    return async (req, res) => {
        try {
            await handler(req, res);
        } catch (error) {
            sendApiError(res, error);
        }
    };
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function base32Encode(buffer) {
    let bits = 0;
    let value = 0;
    let output = '';

    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;

        while (bits >= 5) {
            output += base32Alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }

    if (bits > 0) {
        output += base32Alphabet[(value << (5 - bits)) & 31];
    }

    return output;
}

function base32Decode(value) {
    const normalized = String(value || '')
        .toUpperCase()
        .replace(/=+$/g, '')
        .replace(/[^A-Z2-7]/g, '');

    let bits = 0;
    let current = 0;
    const output = [];

    for (const char of normalized) {
        const index = base32Alphabet.indexOf(char);
        if (index === -1) {
            continue;
        }

        current = (current << 5) | index;
        bits += 5;

        if (bits >= 8) {
            output.push((current >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }

    return Buffer.from(output);
}

function generateTotpSecret() {
    return base32Encode(crypto.randomBytes(20));
}

function generateHotp(secret, counter) {
    const key = base32Decode(secret);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter));
    const digest = crypto.createHmac('sha1', key).update(counterBuffer).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const code = (
        ((digest[offset] & 0x7f) << 24)
        | ((digest[offset + 1] & 0xff) << 16)
        | ((digest[offset + 2] & 0xff) << 8)
        | (digest[offset + 3] & 0xff)
    ) % 1000000;

    return String(code).padStart(6, '0');
}

function verifyTotpToken(token, secret) {
    const normalized = String(token || '').replace(/\s+/g, '');
    if (!/^\d{6}$/.test(normalized) || !secret) {
        return false;
    }

    const counter = Math.floor(Date.now() / 30000);
    for (let offset = -1; offset <= 1; offset += 1) {
        if (generateHotp(secret, counter + offset) === normalized) {
            return true;
        }
    }

    return false;
}

function normalizeBackupCode(value) {
    return String(value || '')
        .toUpperCase()
        .replace(/[^A-Z0-9]/g, '');
}

function generateBackupCode() {
    let raw = '';
    for (let index = 0; index < 10; index += 1) {
        raw += backupCodeAlphabet[Math.floor(Math.random() * backupCodeAlphabet.length)];
    }

    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

function generateBackupCodes(count = 8) {
    return Array.from({ length: count }, () => generateBackupCode());
}

function consumeBackupCode(candidate, storedHashes = []) {
    const normalizedCandidate = normalizeBackupCode(candidate);
    if (!normalizedCandidate) {
        return null;
    }

    for (let index = 0; index < storedHashes.length; index += 1) {
        if (verifyPassword(normalizedCandidate, storedHashes[index])) {
            return storedHashes.filter((_entry, hashIndex) => hashIndex !== index);
        }
    }

    return null;
}

function buildTotpUri(username, secret) {
    const accountLabel = encodeURIComponent(`Quarky:${username}`);
    const issuer = encodeURIComponent('Quarky');
    return `otpauth://totp/${accountLabel}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

async function getAuthenticatedUser(req) {
    const cookies = parseCookies(req.headers.cookie || '');
    if (!cookies.session) {
        return null;
    }

    const user = await findUserBySessionToken(cookies.session);
    if (!user) {
        return null;
    }

    return {
        ...user,
        sessionToken: cookies.session
    };
}

function requireAuth(handler) {
    return withApiError(async (req, res) => {
        const [user, settings] = await Promise.all([
            getAuthenticatedUser(req),
            getSiteSettings()
        ]);

        if (!user) {
            return res.status(401).json({ error: 'Not logged in.' });
        }

        if (user.isBanned && !isAllowedDuringBanRestriction(req.path)) {
            return res.status(403).json({
                error: getBanMessage(user),
                banned: true,
                banReason: user.banReason || '',
                banExpiresAt: user.banExpiresAt || null
            });
        }

        if (!user.isApproved && user.role !== 'admin') {
            await deleteSession(user.sessionToken);
            res.setHeader('Set-Cookie', clearSessionCookie());
            return res.status(403).json({ error: 'Your account is waiting for admin approval.', requiresApproval: true });
        }

        if (!settings.loginEnabled && user.role !== 'admin') {
            await deleteSession(user.sessionToken);
            res.setHeader('Set-Cookie', clearSessionCookie());
            return res.status(403).json({ error: 'Login is currently limited to admin accounts only.' });
        }

        if (user.forcePasswordReset && !isAllowedDuringForcedPasswordReset(req.path)) {
            return res.status(403).json({
                error: 'You must change your password before using the rest of the site.',
                forcePasswordReset: true
            });
        }

        return handler(req, res, user, settings);
    });
}

function requireAdmin(handler) {
    return requireAuth(async (req, res, user, settings) => {
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access is required.' });
        }

        return handler(req, res, user, settings);
    });
}

app.get('/api/site-settings', withApiError(async (req, res) => {
    const settings = await getSiteSettings();
    res.json({ settings: toClientSettings(settings) });
}));

app.get('/api/home', withApiError(async (req, res) => {
    const [settings, stats, featuredProjects, newestProjects, rawLatestUploads] = await Promise.all([
        getSiteSettings(),
        getSiteStats(),
        getProjects({ publicOnly: true, featuredOnly: true, limit: 4 }),
        getProjects({ publicOnly: true, limit: 12 }),
        getLatestUploads(16)
    ]);
    const viewer = await getAuthenticatedUser(req);
    const allPublicProjects = await getProjects({ publicOnly: true });

    const latestUploads = [];
    for (const upload of rawLatestUploads) {
        if (!upload.projectId) {
            continue;
        }

        const relatedProject = await getProjectById(upload.projectId);
        if (!relatedProject || relatedProject.visibility !== 'public') {
            continue;
        }

        latestUploads.push({
            ...upload,
            projectId: relatedProject.id,
            projectTitle: relatedProject.title,
            ownerAvatarMedia: relatedProject.ownerAvatarMedia || null
        });

        if (latestUploads.length >= 8) {
            break;
        }
    }

    const trendingProjects = [...allPublicProjects]
        .sort((left, right) => calculateTrendingScore(right) - calculateTrendingScore(left))
        .slice(0, 6);

    let followedFeed = [];
    if (viewer) {
        const followedUserIds = await getFollowedUserIds(viewer.id);
        followedFeed = allPublicProjects
            .filter((project) => matchesFollowedCreators(project, followedUserIds))
            .sort((left, right) => new Date(right.updatedAt) - new Date(left.updatedAt))
            .slice(0, 6);
    }

    res.json({
        settings: toClientSettings(settings),
        stats,
        featuredProjects: featuredProjects.map(sanitizeProjectForClient),
        newestProjects: newestProjects.map(sanitizeProjectForClient),
        latestUploads,
        trendingProjects: trendingProjects.map(sanitizeProjectForClient),
        followedFeed: followedFeed.map(sanitizeProjectForClient)
    });
}));

app.get('/api/trending', withApiError(async (_req, res) => {
    const projects = await getProjects({ publicOnly: true });
    const trendingProjects = [...projects]
        .sort((left, right) => calculateTrendingScore(right) - calculateTrendingScore(left))
        .map((project) => ({
            ...sanitizeProjectForClient(project),
            trendingScore: Number(calculateTrendingScore(project).toFixed(2))
        }));

    res.json({ projects: trendingProjects });
}));

app.get('/api/feed', requireAuth(async (_req, res, user) => {
    const followedUserIds = await getFollowedUserIds(user.id);
    if (!followedUserIds.length) {
        return res.json({ projects: [] });
    }

    const projects = await getProjects({ publicOnly: true });
    const followedFeed = projects
        .filter((project) => matchesFollowedCreators(project, followedUserIds))
        .sort((left, right) => new Date(right.updatedAt) - new Date(left.updatedAt))
        .slice(0, 20);

    res.json({ projects: followedFeed.map(sanitizeProjectForClient) });
}));

app.get('/api/projects', withApiError(async (req, res) => {
    const search = String(req.query.q || '').trim().toLowerCase();
    const category = String(req.query.category || '').trim().toLowerCase();
    const tag = String(req.query.tag || '').trim().toLowerCase();
    const featuredOnly = normalizeBoolean(req.query.featured);

    let projects = await getProjects({ publicOnly: true, featuredOnly });

    if (search) {
        projects = projects.filter((project) => [
            project.title,
            project.summary,
            project.description,
            project.owner,
            project.type,
            ...(project.tags || [])
        ].some((value) => String(value || '').toLowerCase().includes(search)));
    }

    if (category) {
        projects = projects.filter((project) => String(project.type || '').trim().toLowerCase() === category);
    }

    if (tag) {
        projects = projects.filter((project) => (project.tags || []).includes(tag));
    }

    res.json({ projects: projects.map(sanitizeProjectForClient) });
}));

app.get('/api/projects/:id', withApiError(async (req, res) => {
    const [viewer, project] = await Promise.all([
        getAuthenticatedUser(req),
        getProjectById(req.params.id)
    ]);

    if (!project || !canViewProject(project, viewer)) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    await incrementProjectViewCount(project.id);
    const refreshedProject = await getProjectById(req.params.id);
    const likedByViewer = viewer ? await userHasLikedProject(refreshedProject.id, viewer.id) : false;

    res.json({
        project: sanitizeProjectForClient(refreshedProject),
        likedByViewer,
        canEdit: canManageProject(refreshedProject, viewer)
    });
}));

app.get('/api/projects/:id/comments', withApiError(async (req, res) => {
    const [viewer, project] = await Promise.all([
        getAuthenticatedUser(req),
        getProjectById(req.params.id)
    ]);

    if (!project || !canViewProject(project, viewer)) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    const includeHidden = Boolean(viewer && (viewer.role === 'admin' || canManageProject(project, viewer)));
    const comments = await getCommentsForProject(project.id, { includeHidden });
    res.json({ comments });
}));

app.post('/api/projects/:id/comments', projectMutationLimiter, requireAuth(async (req, res, user) => {
    const settings = await getSiteSettings();
    if (isNewAccountRestricted(user, settings)) {
        return res.status(403).json({ error: getNewAccountRestrictionMessage(settings) });
    }

    const cooldownMessage = await enforceLowTrustCooldown(user, settings, 'comment');
    if (cooldownMessage) {
        return res.status(429).json({ error: cooldownMessage });
    }

    const project = await getProjectById(req.params.id);
    if (!project || !canViewProject(project, user)) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    const content = String(req.body.content || '').trim();
    if (!content) {
        return res.status(400).json({ error: 'Write a comment before sending it.' });
    }

    if (content.length > 2000) {
        return res.status(400).json({ error: 'Comments must stay under 2000 characters.' });
    }

    const blockedWord = findBlockedWord(settings, content);
    if (blockedWord) {
        return res.status(400).json({ error: `That message includes a blocked word: ${blockedWord}` });
    }

    const comment = await createComment({
        projectId: project.id,
        authorUserId: user.id,
        content
    });

    if (project.ownerDbId && project.ownerDbId !== user.id) {
        await createNotification({
            userId: project.ownerDbId,
            type: 'comment',
            message: `${user.username} commented on ${project.title}.`,
            link: `/project?id=${project.id}`
        });
    }

    res.status(201).json({ comment });
}));

app.post('/api/projects/:id/like', projectMutationLimiter, requireAuth(async (req, res, user) => {
    const settings = await getSiteSettings();
    if (isNewAccountRestricted(user, settings)) {
        return res.status(403).json({ error: getNewAccountRestrictionMessage(settings) });
    }

    const project = await getProjectById(req.params.id);
    if (!project || !canViewProject(project, user)) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    const liked = await toggleProjectLike(project.id, user.id);
    const refreshedProject = await getProjectById(project.id);

    if (liked && project.ownerDbId && project.ownerDbId !== user.id) {
        await createNotification({
            userId: project.ownerDbId,
            type: 'like',
            message: `${user.username} favorited ${project.title}.`,
            link: `/project?id=${project.id}`
        });
    }

    res.json({
        liked,
        project: sanitizeProjectForClient(refreshedProject)
    });
}));

app.post('/api/projects/:id/report', projectMutationLimiter, requireAuth(async (req, res, user) => {
    const settings = await getSiteSettings();
    if (isNewAccountRestricted(user, settings)) {
        return res.status(403).json({ error: getNewAccountRestrictionMessage(settings) });
    }

    const project = await getProjectById(req.params.id);
    if (!project || !canViewProject(project, user)) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    const reason = normalizeReportReason(req.body.reason);
    const details = String(req.body.details || '').trim().slice(0, 1500);
    const report = await createReport({
        reporterUserId: user.id,
        targetType: 'project',
        targetId: project.id,
        reason,
        details
    });

    res.status(201).json({ report });
}));

app.delete('/api/comments/:id', requireAuth(async (req, res, user) => {
    const comment = await getCommentById(req.params.id);
    if (!comment) {
        return res.status(404).json({ error: 'Comment not found.' });
    }

    const project = await getProjectById(comment.projectId);
    const canDelete = Boolean(
        user.role === 'admin'
        || comment.authorUserId === user.userId
        || (project && canManageProject(project, user))
    );

    if (!canDelete) {
        return res.status(403).json({ error: 'You cannot remove this comment.' });
    }

    await deleteComment(comment.id);
    res.json({ ok: true });
}));

app.post('/api/comments/:id/report', projectMutationLimiter, requireAuth(async (req, res, user) => {
    const settings = await getSiteSettings();
    if (isNewAccountRestricted(user, settings)) {
        return res.status(403).json({ error: getNewAccountRestrictionMessage(settings) });
    }

    const comment = await getCommentById(req.params.id);
    if (!comment) {
        return res.status(404).json({ error: 'Comment not found.' });
    }

    const project = await getProjectById(comment.projectId);
    if (!project || !canViewProject(project, user)) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    const report = await createReport({
        reporterUserId: user.id,
        targetType: 'comment',
        targetId: comment.id,
        reason: normalizeReportReason(req.body.reason),
        details: String(req.body.details || '').trim().slice(0, 1500)
    });

    res.status(201).json({ report });
}));

app.get('/api/users/:userId', withApiError(async (req, res) => {
    const [viewer, settings] = await Promise.all([
        getAuthenticatedUser(req),
        getSiteSettings()
    ]);
    const profile = await getPublicUserProfile(req.params.userId, viewer ? viewer.id : null);
    if (!profile) {
        return res.status(404).json({ error: 'User not found.' });
    }

    res.json({
        user: sanitizePublicUser(profile.user, settings),
        projects: profile.projects.map(sanitizeProjectForClient),
        isFollowing: Boolean(profile.isFollowing)
    });
}));

app.post('/api/users/:userId/follow', requireAuth(async (req, res, user) => {
    const settings = await getSiteSettings();
    if (isNewAccountRestricted(user, settings)) {
        return res.status(403).json({ error: getNewAccountRestrictionMessage(settings) });
    }

    const targetUser = await findUserByPublicId(req.params.userId);
    if (!targetUser) {
        return res.status(404).json({ error: 'User not found.' });
    }

    if (targetUser.id === user.id) {
        return res.status(400).json({ error: 'You cannot follow yourself.' });
    }

    const alreadyFollowing = await isFollowingUser(user.id, targetUser.id);
    if (alreadyFollowing) {
        await unfollowUser(user.id, targetUser.id);
    } else {
        await followUser(user.id, targetUser.id);
        await createNotification({
            userId: targetUser.id,
            type: 'follow',
            message: `${user.username} started following you.`,
            link: `/user?id=${targetUser.userId}`
        });
    }

    const refreshedProfile = await getPublicUserProfile(targetUser.userId, user.id);
    res.json({
        isFollowing: !alreadyFollowing,
        followerCount: refreshedProfile ? refreshedProfile.user.followerCount : 0
    });
}));

app.get('/api/me', requireAuth(async (_req, res, user, settings) => {
    const [projects, notifications] = await Promise.all([
        getProjectsForUser(user.id),
        getNotificationsForUser(user.id)
    ]);

    res.json({
        user: sanitizeCurrentUser(user, settings),
        projects: projects.map(sanitizeProjectForClient),
        notifications,
        settings: toClientSettings(settings)
    });
}));

app.post('/api/register', authRateLimiter, withApiError(async (req, res) => {
    const settings = await getSiteSettings();
    if (!settings.registrationsEnabled) {
        return res.status(403).json({ error: 'Registration is currently disabled.' });
    }

    const username = String(req.body.username || '').trim();
    const email = normalizeEmailAddress(req.body.email);
    const password = String(req.body.password || '');
    const inviteCode = String(req.body.inviteCode || '').trim().toUpperCase();

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required.' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Enter a valid email address.' });
    }

    if (password.length < 12) {
        return res.status(400).json({ error: 'Use a password with at least 12 characters.' });
    }

    if (isDisposableEmail(email)) {
        return res.status(400).json({ error: 'Use a permanent email address. Disposable inboxes are not allowed.' });
    }

    const blockedUsername = findBlockedWord(settings, username);
    if (blockedUsername) {
        return res.status(400).json({ error: `That username contains a blocked word: ${blockedUsername}` });
    }

    if (isRecaptchaEnabled()) {
        const captchaToken = String(req.body.captchaToken || '').trim();
        if (!captchaToken) {
            return res.status(400).json({ error: 'Complete the captcha check before creating your account.' });
        }

        const captchaResult = await verifyRecaptchaToken(captchaToken, req.ip);
        if (!captchaResult.success) {
            return res.status(400).json({
                error: 'Captcha verification failed. Please try again.',
                details: captchaResult['error-codes'] || []
            });
        }
    }

    const existingUser = await findUserByUsername(username);
    if (existingUser) {
        return res.status(409).json({ error: 'That username is already taken.' });
    }

    const existingEmail = await findUserByEmail(email);
    if (existingEmail) {
        return res.status(409).json({ error: 'That email address is already in use.' });
    }

    if (settings.inviteOnlyEnabled) {
        if (!inviteCode) {
            return res.status(400).json({ error: 'An invite code is required to register right now.' });
        }

        const activeInvite = await getInviteCode(inviteCode);
        if (!activeInvite || activeInvite.isDisabled || activeInvite.usesRemaining < 1 || (activeInvite.expiresAt && new Date(activeInvite.expiresAt).getTime() <= Date.now())) {
            return res.status(400).json({ error: 'That invite code is invalid or expired.' });
        }
    }

    const user = await createUser({
        username,
        email,
        password,
        role: 'user',
        emailVerified: true,
        isApproved: !settings.approvalRequired
    });

    if (settings.inviteOnlyEnabled) {
        const consumed = await consumeInviteCode(inviteCode);
        if (!consumed) {
            await deleteUserByPublicId(user.userId);
            return res.status(400).json({ error: 'That invite code is no longer available. Try another one.' });
        }
    }

    res.status(201).json({
        ok: true,
        message: settings.approvalRequired
            ? 'Account created. Your account is waiting for admin approval before you can log in.'
            : 'Account created. You can log in now.'
    });
}));

app.post('/api/login', authRateLimiter, withApiError(async (req, res) => {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const otp = String(req.body.otp || '').trim();
    const clientIp = String(req.ip || req.socket?.remoteAddress || '').trim();

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    const loginAttemptState = await getLoginAttemptState(username, clientIp);
    if (loginAttemptState.isLocked) {
        return sendLoginLockoutResponse(res, loginAttemptState.lockedUntil);
    }

    const user = await findUserByUsername(username);
    if (!user || !verifyPassword(password, user.passwordHash)) {
        const failedAttemptState = await recordFailedLoginAttempt(username, clientIp, {
            maxAttempts: loginMaxFailedAttempts,
            lockMinutes: loginLockoutMinutes
        });
        await sleep(350);
        if (failedAttemptState.isLocked) {
            return sendLoginLockoutResponse(res, failedAttemptState.lockedUntil);
        }
        return res.status(401).json({ error: 'Invalid username or password.' });
    }

    if (!user.isApproved && user.role !== 'admin') {
        return res.status(403).json({
            error: 'Your account is waiting for admin approval.',
            requiresApproval: true
        });
    }

    const settings = await getSiteSettings();
    if (!settings.loginEnabled && user.role !== 'admin') {
        return res.status(403).json({ error: 'Login is currently limited to admin accounts only.' });
    }

    if (user.twoFactorEnabled) {
        if (!otp) {
            return res.json({
                requiresTwoFactor: true,
                message: 'Enter your authenticator code or one-time backup code to finish logging in.'
            });
        }

        const backupCodesRemaining = consumeBackupCode(otp, user.twoFactorBackupCodeHashes || []);
        const otpValid = verifyTotpToken(otp, user.twoFactorSecret);

        if (!otpValid && !backupCodesRemaining) {
            const failedAttemptState = await recordFailedLoginAttempt(username, clientIp, {
                maxAttempts: loginMaxFailedAttempts,
                lockMinutes: loginLockoutMinutes
            });
            await sleep(350);
            if (failedAttemptState.isLocked) {
                return sendLoginLockoutResponse(res, failedAttemptState.lockedUntil);
            }
            return res.status(401).json({
                error: 'Invalid authenticator or backup code.',
                requiresTwoFactor: true
            });
        }

        if (backupCodesRemaining) {
            await replaceUserTwoFactorBackupCodes(user.id, backupCodesRemaining);
        }
    }

    await clearLoginAttemptState(username, clientIp);
    const session = await createSession(user.id);
    res.setHeader('Set-Cookie', buildSessionCookie(session.token));
    res.json({
        user: sanitizeCurrentUser(user)
    });
}));

app.post('/api/logout', withApiError(async (req, res) => {
    const cookies = parseCookies(req.headers.cookie || '');
    if (cookies.session) {
        await deleteSession(cookies.session);
    }

    res.setHeader('Set-Cookie', clearSessionCookie());
    res.json({ ok: true });
}));

app.post('/api/profile/2fa/setup', requireAuth(async (_req, res, user) => {
    if (user.twoFactorEnabled) {
        return res.status(400).json({ error: 'Two-factor authentication is already enabled. Disable it before creating a new secret.' });
    }

    const secret = generateTotpSecret();
    await storePendingTwoFactorSecret(user.id, secret);

    res.json({
        secret,
        manualEntryKey: secret.match(/.{1,4}/g).join(' '),
        otpAuthUrl: buildTotpUri(user.username, secret)
    });
}));

app.post('/api/profile/2fa/enable', requireAuth(async (req, res, user) => {
    const token = String(req.body.token || '').trim();
    if (!token) {
        return res.status(400).json({ error: 'Enter the authenticator code to enable two-factor authentication.' });
    }

    const freshUser = await findUserById(user.id);
    if (!freshUser || !freshUser.twoFactorSecret) {
        return res.status(400).json({ error: 'Create a 2FA secret first.' });
    }

    if (!verifyTotpToken(token, freshUser.twoFactorSecret)) {
        return res.status(400).json({ error: 'That authenticator code is not valid.' });
    }

    const backupCodes = generateBackupCodes();
    const backupCodeHashes = backupCodes.map((code) => hashPassword(normalizeBackupCode(code)));
    await enableUserTwoFactor(user.id, freshUser.twoFactorSecret, backupCodeHashes);

    res.json({
        ok: true,
        backupCodes
    });
}));

app.post('/api/profile/2fa/disable', requireAuth(async (req, res, user) => {
    const password = String(req.body.password || '');
    const token = String(req.body.token || '').trim();

    const freshUser = await findUserById(user.id);
    if (!freshUser) {
        return res.status(404).json({ error: 'User not found.' });
    }

    if (!verifyPassword(password, freshUser.passwordHash)) {
        await sleep(350);
        return res.status(403).json({ error: 'Your password was not correct.' });
    }

    if (freshUser.twoFactorEnabled) {
        const otpValid = verifyTotpToken(token, freshUser.twoFactorSecret);
        const backupCodesRemaining = consumeBackupCode(token, freshUser.twoFactorBackupCodeHashes || []);
        if (!otpValid && !backupCodesRemaining) {
            return res.status(400).json({ error: 'Enter a valid authenticator code or backup code to disable two-factor authentication.' });
        }
    }

    await disableUserTwoFactor(user.id);
    res.json({ ok: true });
}));

app.patch('/api/profile', projectMutationLimiter, requireAuth(async (req, res, user, settings) => {
    await runUploadMiddleware(req, res, user, settings);
    const avatarUploads = await persistUploadedFiles(getUploadGroup(req, 'avatarFile'));
    const bannerUploads = await persistUploadedFiles(getUploadGroup(req, 'bannerFile'));
    const incomingUploads = collectStoredEntries(avatarUploads, bannerUploads);

    if (isNewAccountRestricted(user, settings) && incomingUploads.length > 0) {
        await removeStoredFiles(incomingUploads);
        return res.status(403).json({ error: getNewAccountRestrictionMessage(settings) });
    }

    if (!settings.uploadsEnabled && incomingUploads.length > 0) {
        await removeStoredFiles(incomingUploads);
        return res.status(403).json({ error: 'Profile uploads are currently disabled.' });
    }

    const removeAvatar = normalizeBoolean(req.body.removeAvatar);
    const removeBanner = normalizeBoolean(req.body.removeBanner);
    const nextAvatar = removeAvatar ? null : (avatarUploads[0] || user.avatarMedia || null);
    const nextBanner = removeBanner ? null : (bannerUploads[0] || user.bannerMedia || null);
    const staleEntries = [];

    if ((removeAvatar || avatarUploads[0]) && user.avatarMedia && user.avatarMedia.storedName !== (nextAvatar && nextAvatar.storedName)) {
        staleEntries.push(user.avatarMedia);
    }

    if ((removeBanner || bannerUploads[0]) && user.bannerMedia && user.bannerMedia.storedName !== (nextBanner && nextBanner.storedName)) {
        staleEntries.push(user.bannerMedia);
    }

    try {
        const updatedUser = await updateUserProfile(user.id, {
            bio: String(req.body.bio || '').trim().slice(0, 1000),
            avatarMedia: nextAvatar,
            bannerMedia: nextBanner
        });

        await removeStoredFiles(staleEntries);
        res.json({ user: sanitizeCurrentUser(updatedUser) });
    } catch (error) {
        await removeStoredFiles(incomingUploads);
        throw error;
    }
}));

app.post('/api/profile/password', requireAuth(async (req, res, user) => {
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword = String(req.body.newPassword || '');

    if (!verifyPassword(currentPassword, user.passwordHash)) {
        await sleep(350);
        return res.status(403).json({ error: 'Your current password was not correct.' });
    }

    if (newPassword.length < 12) {
        return res.status(400).json({ error: 'Use a new password with at least 12 characters.' });
    }

    const updatedUser = await updateUserPassword(user.id, newPassword);
    await createAuditLog({
        actorUserId: user.id,
        action: 'password_change',
        targetType: 'user',
        targetId: user.userId,
        details: 'User changed their own password.'
    });

    res.json({ user: sanitizeCurrentUser(updatedUser) });
}));

app.post('/api/me/notifications/read', requireAuth(async (_req, res, user) => {
    await markAllNotificationsRead(user.id);
    res.json({ ok: true });
}));

app.post('/api/projects', projectMutationLimiter, requireAuth(async (req, res, user, settings) => {
    if (!settings.uploadsEnabled) {
        return res.status(403).json({ error: 'Project creation is disabled while uploads are disabled.' });
    }

    if (isNewAccountRestricted(user, settings)) {
        return res.status(403).json({ error: getNewAccountRestrictionMessage(settings) });
    }

    if (settings.projectLimitEnabled && user.role !== 'admin') {
        const projectCount = await countProjectsForUser(user.id);
        if (projectCount >= settings.maxProjectsPerUser) {
            return res.status(403).json({ error: `You have reached the current project limit of ${settings.maxProjectsPerUser}.` });
        }
    }

    const cooldownMessage = await enforceLowTrustCooldown(user, settings, 'project');
    if (cooldownMessage) {
        return res.status(429).json({ error: cooldownMessage });
    }

    await runUploadMiddleware(req, res, user, settings);
    const uploadedFiles = await persistUploadedFiles(getUploadGroup(req, 'projectFiles'));
    const screenshotFiles = await persistUploadedFiles(getUploadGroup(req, 'projectScreenshots'));
    const payload = normalizeProjectPayload(req.body);
    const validationError = validateProjectPayload(payload);
    if (validationError) {
        await removeStoredFiles(collectStoredEntries(uploadedFiles, screenshotFiles));
        return res.status(400).json({ error: validationError });
    }

    const blockedWord = findBlockedWord(
        settings,
        payload.title,
        payload.summary,
        payload.description,
        payload.tags,
        payload.changelog,
        payload.devlogs,
        payload.knownBugs,
        payload.owners
    );
    if (blockedWord) {
        await removeStoredFiles(collectStoredEntries(uploadedFiles, screenshotFiles));
        return res.status(400).json({ error: `This project includes a blocked word: ${blockedWord}` });
    }

    const coOwners = await resolveProjectCoOwners(payload.owners, user);

    try {
        const project = await createProject({
            ownerUserId: user.id,
            coOwnerUserIds: coOwners.userIds,
            ...payload,
            downloadables: uploadedFiles,
            screenshots: screenshotFiles,
            featured: user.role === 'admin' && payload.featured
        });

        await createAuditLog({
            actorUserId: user.id,
            action: 'project_create',
            targetType: 'project',
            targetId: project.id,
            details: project.title
        });

        res.status(201).json({ project: sanitizeProjectForClient(project) });
    } catch (error) {
        await removeStoredFiles(collectStoredEntries(uploadedFiles, screenshotFiles));
        throw error;
    }
}));

app.put('/api/projects/:id', projectMutationLimiter, requireAuth(async (req, res, user, settings) => {
    const existingProject = await getProjectById(req.params.id);
    if (!existingProject) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    if (!canManageProject(existingProject, user)) {
        return res.status(403).json({ error: 'You can only edit your own projects.' });
    }

    if (isNewAccountRestricted(user, settings)) {
        return res.status(403).json({ error: getNewAccountRestrictionMessage(settings) });
    }

    await runUploadMiddleware(req, res, user, settings);
    const uploadedFiles = await persistUploadedFiles(getUploadGroup(req, 'projectFiles'));
    const screenshotFiles = await persistUploadedFiles(getUploadGroup(req, 'projectScreenshots'));

    if (!settings.uploadsEnabled && collectStoredEntries(uploadedFiles, screenshotFiles).length > 0) {
        await removeStoredFiles(collectStoredEntries(uploadedFiles, screenshotFiles));
        return res.status(403).json({ error: 'File uploads are currently disabled.' });
    }

    const payload = normalizeProjectPayload(req.body);
    const validationError = validateProjectPayload(payload);
    if (validationError) {
        await removeStoredFiles(collectStoredEntries(uploadedFiles, screenshotFiles));
        return res.status(400).json({ error: validationError });
    }

    const blockedWord = findBlockedWord(
        settings,
        payload.title,
        payload.summary,
        payload.description,
        payload.tags,
        payload.changelog,
        payload.devlogs,
        payload.knownBugs,
        payload.owners
    );
    if (blockedWord) {
        await removeStoredFiles(collectStoredEntries(uploadedFiles, screenshotFiles));
        return res.status(400).json({ error: `This project includes a blocked word: ${blockedWord}` });
    }

    const coOwners = await resolveProjectCoOwners(payload.owners, user);

    const removedKeys = new Set(parseRemovedFiles(req.body.removedFiles));
    const removedScreenshotKeys = new Set(parseRemovedFiles(req.body.removedScreenshots));
    const removableDownloadables = (existingProject.downloadables || []).filter(
        (entry) => entry && removedKeys.has(getDownloadableKey(entry))
    );
    const keptDownloadables = (existingProject.downloadables || []).filter(
        (entry) => !(entry && removedKeys.has(getDownloadableKey(entry)))
    );
    const removableScreenshots = (existingProject.screenshots || []).filter(
        (entry) => entry && removedScreenshotKeys.has(getDownloadableKey(entry))
    );
    const keptScreenshots = (existingProject.screenshots || []).filter(
        (entry) => !(entry && removedScreenshotKeys.has(getDownloadableKey(entry)))
    );

    try {
        const project = await updateProject(req.params.id, {
            ...payload,
            downloadables: [...keptDownloadables, ...uploadedFiles],
            screenshots: [...keptScreenshots, ...screenshotFiles],
            coOwnerUserIds: coOwners.userIds,
            featured: user.role === 'admin' ? payload.featured : existingProject.featured
        });

        await removeStoredFiles([...removableDownloadables, ...removableScreenshots]);
        await createAuditLog({
            actorUserId: user.id,
            action: 'project_update',
            targetType: 'project',
            targetId: project.id,
            details: project.title
        });

        res.json({ project: sanitizeProjectForClient(project) });
    } catch (error) {
        await removeStoredFiles(collectStoredEntries(uploadedFiles, screenshotFiles));
        throw error;
    }
}));

app.delete('/api/projects/:id', requireAuth(async (req, res, user) => {
    const existingProject = await getProjectById(req.params.id);
    if (!existingProject) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    if (!canManageProject(existingProject, user)) {
        return res.status(403).json({ error: 'You can only remove your own projects.' });
    }

    await createAuditLog({
        actorUserId: user.id,
        action: 'project_delete',
        targetType: 'project',
        targetId: existingProject.id,
        details: existingProject.title
    });
    await deleteProject(req.params.id);
    await removeProjectStoredFiles(existingProject);
    res.json({ ok: true });
}));

app.get('/api/admin/overview', requireAdmin(async (req, res, _user, settings) => {
    const [users, projects, reports, auditLogs, storage, inviteCodes] = await Promise.all([
        getAllUsers(),
        getProjects(),
        getReports(),
        getAuditLogs(200),
        getStorageDashboard(),
        listInviteCodes()
    ]);
    res.json({
        settings: toAdminSettings(settings),
        users: users.map((user) => ({
            ...sanitizeCurrentUser(user, settings),
            bannedAt: user.bannedAt,
            banReason: user.banReason || '',
            banExpiresAt: user.banExpiresAt || null,
            approvedAt: user.approvedAt,
            projectCount: user.projectCount || 0
        })),
        projects: projects.map(sanitizeProjectForClient),
        reports,
        auditLogs,
        storage,
        inviteCodes
    });
}));

app.patch('/api/admin/settings', requireAdmin(async (req, res, user) => {
    const updates = {};

    if (Object.prototype.hasOwnProperty.call(req.body, 'registrationsEnabled')) {
        updates.registrationsEnabled = normalizeBoolean(req.body.registrationsEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'loginEnabled')) {
        updates.loginEnabled = normalizeBoolean(req.body.loginEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'uploadsEnabled')) {
        updates.uploadsEnabled = normalizeBoolean(req.body.uploadsEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'projectLimitEnabled')) {
        updates.projectLimitEnabled = normalizeBoolean(req.body.projectLimitEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'maxProjectsPerUser')) {
        updates.maxProjectsPerUser = normalizePositiveInteger(req.body.maxProjectsPerUser, 10);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'uploadSizeLimitEnabled')) {
        updates.uploadSizeLimitEnabled = normalizeBoolean(req.body.uploadSizeLimitEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'maxUploadSizeMb')) {
        updates.maxUploadSizeMb = normalizePositiveInteger(req.body.maxUploadSizeMb, 25);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'inviteOnlyEnabled')) {
        updates.inviteOnlyEnabled = normalizeBoolean(req.body.inviteOnlyEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'approvalRequired')) {
        updates.approvalRequired = normalizeBoolean(req.body.approvalRequired);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'newAccountRestrictionsEnabled')) {
        updates.newAccountRestrictionsEnabled = normalizeBoolean(req.body.newAccountRestrictionsEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'newAccountRestrictionHours')) {
        updates.newAccountRestrictionHours = normalizePositiveInteger(req.body.newAccountRestrictionHours, 24);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'announcementEnabled')) {
        updates.announcementEnabled = normalizeBoolean(req.body.announcementEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'announcementText')) {
        updates.announcementText = String(req.body.announcementText || '');
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'announcementLink')) {
        updates.announcementLink = String(req.body.announcementLink || '');
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'trustLevelEnabled')) {
        updates.trustLevelEnabled = normalizeBoolean(req.body.trustLevelEnabled);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'lowTrustAgeHours')) {
        updates.lowTrustAgeHours = normalizePositiveInteger(req.body.lowTrustAgeHours, 72);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'lowTrustCommentCooldownSeconds')) {
        updates.lowTrustCommentCooldownSeconds = Math.max(0, Number(req.body.lowTrustCommentCooldownSeconds) || 0);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'lowTrustProjectCooldownMinutes')) {
        updates.lowTrustProjectCooldownMinutes = Math.max(0, Number(req.body.lowTrustProjectCooldownMinutes) || 0);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, 'wordBlacklist')) {
        updates.wordBlacklist = String(req.body.wordBlacklist || '');
    }

    const settings = await updateSiteSettings(updates);
    await createAuditLog({
        actorUserId: user.id,
        action: 'settings_update',
        targetType: 'site_settings',
        targetId: '1',
        details: updates
    });
    res.json({ settings: toAdminSettings(settings) });
}));

app.post('/api/admin/invites', requireAdmin(async (req, res, adminUser) => {
    const usesRemaining = normalizePositiveInteger(req.body.usesRemaining, 1);
    const expiresInDaysRaw = String(req.body.expiresInDays || '').trim();
    const expiresAt = expiresInDaysRaw
        ? new Date(Date.now() + normalizePositiveInteger(expiresInDaysRaw, 7) * 24 * 60 * 60 * 1000)
        : null;

    const invite = await createInviteCode({
        createdByUserId: adminUser.id,
        usesRemaining,
        expiresAt
    });

    await createAuditLog({
        actorUserId: adminUser.id,
        action: 'invite_created',
        targetType: 'invite',
        targetId: invite.code,
        details: `uses=${invite.usesRemaining}`
    });

    res.status(201).json({ invite });
}));

app.delete('/api/admin/invites/:code', requireAdmin(async (req, res, adminUser) => {
    const invite = await getInviteCode(req.params.code);
    if (!invite) {
        return res.status(404).json({ error: 'Invite code not found.' });
    }

    await revokeInviteCode(invite.code);
    await createAuditLog({
        actorUserId: adminUser.id,
        action: 'invite_revoked',
        targetType: 'invite',
        targetId: invite.code,
        details: invite.code
    });

    res.json({ ok: true });
}));

app.patch('/api/admin/users/:userId/approve', requireAdmin(async (req, res, adminUser) => {
    const targetUser = await findUserByPublicId(req.params.userId);
    if (!targetUser) {
        return res.status(404).json({ error: 'User not found.' });
    }

    if (targetUser.userId === adminUser.userId) {
        return res.status(400).json({ error: 'Change another account instead of your own approval state.' });
    }

    const approved = normalizeBoolean(req.body.approved);
    const updatedUser = await setUserApprovalStatus(targetUser.userId, approved);

    await createAuditLog({
        actorUserId: adminUser.id,
        action: approved ? 'user_approved' : 'user_unapproved',
        targetType: 'user',
        targetId: targetUser.userId,
        details: targetUser.username
    });

    if (approved) {
        await createNotification({
            userId: targetUser.id,
            type: 'account',
            message: 'Your account is now approved and ready to use.',
            link: '/login'
        });
    }

    res.json({ user: sanitizeCurrentUser(updatedUser) });
}));

app.patch('/api/admin/users/:userId/ban', requireAdmin(async (req, res, adminUser) => {
    const targetUser = await findUserByPublicId(req.params.userId);
    if (!targetUser) {
        return res.status(404).json({ error: 'User not found.' });
    }

    if (targetUser.userId === adminUser.userId) {
        return res.status(400).json({ error: 'You cannot ban your own admin account.' });
    }

    const banned = normalizeBoolean(req.body.banned);
    const reason = String(req.body.reason || '').trim();
    const hours = Object.prototype.hasOwnProperty.call(req.body, 'hours')
        ? normalizePositiveInteger(req.body.hours, 0)
        : 0;

    await setUserBanStatus(targetUser.userId, banned, { reason, hours });
    const updatedUser = await findUserByPublicId(targetUser.userId);

    await createAuditLog({
        actorUserId: adminUser.id,
        action: banned ? 'user_ban' : 'user_unban',
        targetType: 'user',
        targetId: targetUser.userId,
        details: banned
            ? `${targetUser.username}${reason ? ` | reason=${reason}` : ''}${hours > 0 ? ` | hours=${hours}` : ''}`
            : targetUser.username
    });

    res.json({ ok: true, user: sanitizeCurrentUser(updatedUser, await getSiteSettings()) });
}));

app.patch('/api/admin/users/:userId/role', requireAdmin(async (req, res, adminUser) => {
    const targetUser = await findUserByPublicId(req.params.userId);
    if (!targetUser) {
        return res.status(404).json({ error: 'User not found.' });
    }

    if (targetUser.userId === adminUser.userId) {
        return res.status(400).json({ error: 'Change another admin account instead of your own role.' });
    }

    const nextRole = String(req.body.role || '').trim().toLowerCase();
    if (!['user', 'admin'].includes(nextRole)) {
        return res.status(400).json({ error: 'Role must be either user or admin.' });
    }

    if (targetUser.role === 'admin' && nextRole !== 'admin') {
        const remainingAdmins = await countAdmins(targetUser.id);
        if (remainingAdmins < 1) {
            return res.status(400).json({ error: 'You must keep at least one admin account.' });
        }
    }

    const updatedUser = await setUserRole(targetUser.userId, nextRole);
    await createAuditLog({
        actorUserId: adminUser.id,
        action: 'user_role_update',
        targetType: 'user',
        targetId: targetUser.userId,
        details: `${targetUser.username} -> ${nextRole}`
    });

    await createNotification({
        userId: targetUser.id,
        type: 'role',
        message: `Your account role is now ${nextRole}.`,
        link: '/profile'
    });

    res.json({ user: sanitizeCurrentUser(updatedUser) });
}));

app.patch('/api/admin/users/:userId/force-reset', requireAdmin(async (req, res, adminUser) => {
    const targetUser = await findUserByPublicId(req.params.userId);
    if (!targetUser) {
        return res.status(404).json({ error: 'User not found.' });
    }

    const force = normalizeBoolean(req.body.force);
    const updatedUser = await setUserForcePasswordReset(targetUser.userId, force);
    if (force) {
        await deleteSessionsForUser(targetUser.id);
        await createNotification({
            userId: targetUser.id,
            type: 'security',
            message: 'An admin requested a password reset for your account.',
            link: '/profile'
        });
    }

    await createAuditLog({
        actorUserId: adminUser.id,
        action: force ? 'force_password_reset' : 'clear_password_reset',
        targetType: 'user',
        targetId: targetUser.userId,
        details: targetUser.username
    });

    res.json({ user: sanitizeCurrentUser(updatedUser) });
}));

app.delete('/api/admin/users/:userId', requireAdmin(async (req, res, adminUser) => {
    const targetUser = await findUserByPublicId(req.params.userId);
    if (!targetUser) {
        return res.status(404).json({ error: 'User not found.' });
    }

    if (targetUser.userId === adminUser.userId) {
        return res.status(400).json({ error: 'You cannot delete your own admin account.' });
    }

    await createAuditLog({
        actorUserId: adminUser.id,
        action: 'user_delete',
        targetType: 'user',
        targetId: targetUser.userId,
        details: targetUser.username
    });
    await deleteUserByPublicId(targetUser.userId);
    res.json({ ok: true });
}));

app.patch('/api/admin/projects/:id/feature', requireAdmin(async (req, res, adminUser) => {
    const project = await getProjectById(req.params.id);
    if (!project) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    const featured = normalizeBoolean(req.body.featured);
    const updatedProject = await updateProject(project.id, {
        title: project.title,
        summary: project.summary,
        description: project.description,
        type: project.type,
        status: project.status,
        visibility: project.visibility,
        tags: project.tags,
        downloadables: project.downloadables,
        screenshots: project.screenshots,
        changelog: project.changelog,
        featured
    });

    await createAuditLog({
        actorUserId: adminUser.id,
        action: featured ? 'project_featured' : 'project_unfeatured',
        targetType: 'project',
        targetId: project.id,
        details: project.title
    });

    res.json({ project: sanitizeProjectForClient(updatedProject) });
}));

app.patch('/api/admin/comments/:id/hide', requireAdmin(async (req, res, adminUser) => {
    const hidden = normalizeBoolean(req.body.hidden);
    const comment = await setCommentHidden(req.params.id, hidden);
    if (!comment) {
        return res.status(404).json({ error: 'Comment not found.' });
    }

    await createAuditLog({
        actorUserId: adminUser.id,
        action: hidden ? 'comment_hidden' : 'comment_unhidden',
        targetType: 'comment',
        targetId: comment.id,
        details: comment.content.slice(0, 120)
    });

    res.json({ comment });
}));

app.patch('/api/admin/reports/:id', requireAdmin(async (req, res, adminUser) => {
    const report = await getReports().then((reports) => reports.find((entry) => entry.id === req.params.id));
    if (!report) {
        return res.status(404).json({ error: 'Report not found.' });
    }

    const status = String(req.body.status || '').trim().toLowerCase();
    if (!['open', 'reviewing', 'actioned', 'dismissed'].includes(status)) {
        return res.status(400).json({ error: 'Pick a valid report status.' });
    }

    const updatedReport = await updateReport(report.id, {
        status,
        adminNote: String(req.body.adminNote || '').trim().slice(0, 2000),
        resolvedByUserId: adminUser.id
    });

    if (report.reporterUserId) {
        const reporter = await findUserByPublicId(report.reporterUserId);
        if (reporter) {
            await createNotification({
                userId: reporter.id,
                type: 'report',
                message: `Your report on ${report.targetType} is now ${status}.`,
                link: report.targetType === 'project' ? `/project?id=${report.targetId}` : '/admin'
            });
        }
    }

    await createAuditLog({
        actorUserId: adminUser.id,
        action: 'report_update',
        targetType: 'report',
        targetId: report.id,
        details: `${report.targetType}:${report.targetId} -> ${status}`
    });

    res.json({ report: updatedReport });
}));

app.delete('/api/admin/reports', requireAdmin(async (_req, res, adminUser) => {
    const existingReports = await getReports();
    const count = existingReports.length;
    await clearAllReports();
    await createAuditLog({
        actorUserId: adminUser.id,
        action: 'reports_cleared',
        targetType: 'report',
        targetId: 'all',
        details: `Removed ${count} report(s)`
    });
    res.json({ ok: true, count });
}));

app.delete('/api/admin/projects/:id', requireAdmin(async (req, res, adminUser) => {
    const project = await getProjectById(req.params.id);
    if (!project) {
        return res.status(404).json({ error: 'Project not found.' });
    }

    await createAuditLog({
        actorUserId: adminUser.id,
        action: 'admin_project_delete',
        targetType: 'project',
        targetId: project.id,
        details: project.title
    });
    await deleteProject(req.params.id);
    await removeProjectStoredFiles(project);
    res.json({ ok: true });
}));

app.get('/files/:storedName', withApiError(async (req, res) => {
    const storedName = normalizeStoredFileName(req.params.storedName);
    if (!storedName) {
        return res.status(404).json({ error: 'File not found.' });
    }

    const [viewer, fileRecord] = await Promise.all([
        getAuthenticatedUser(req),
        getUploadedFileByStoredName(storedName)
    ]);

    if (!fileRecord) {
        return res.status(404).json({ error: 'File not found.' });
    }

    if (fileRecord.targetType === 'project_attachment') {
        const project = await getProjectById(fileRecord.targetId);
        if (!project || !canViewProject(project, viewer)) {
            return res.status(404).json({ error: 'File not found.' });
        }
        await incrementProjectDownloadCount(project.id);
    }

    const filePath = path.join(filesDirectory, storedName);
    try {
        const encryptedPayload = await fs.promises.readFile(filePath);
        const decryptedPayload = decryptFileBuffer(encryptedPayload);
        const requestedName = sanitizeOriginalFileName(String(req.query.name || fileRecord.originalName || storedName));

        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', String(decryptedPayload.length));
        res.setHeader('Content-Disposition', `attachment; filename="${requestedName}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
        return res.send(decryptedPayload);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return res.status(404).json({ error: 'File not found.' });
        }

        throw error;
    }
}));

app.get('/media/:storedName', withApiError(async (req, res) => {
    const storedName = normalizeStoredFileName(req.params.storedName);
    if (!storedName) {
        return res.status(404).json({ error: 'Media not found.' });
    }

    const [viewer, fileRecord] = await Promise.all([
        getAuthenticatedUser(req),
        getUploadedFileByStoredName(storedName)
    ]);

    if (!fileRecord || !isImageMimeType(fileRecord.mimeType)) {
        return res.status(404).json({ error: 'Media not found.' });
    }

    if (fileRecord.targetType === 'project_screenshot') {
        const project = await getProjectById(fileRecord.targetId);
        if (!project || !canViewProject(project, viewer)) {
            return res.status(404).json({ error: 'Media not found.' });
        }
    }

    const filePath = path.join(filesDirectory, storedName);
    try {
        const encryptedPayload = await fs.promises.readFile(filePath);
        const decryptedPayload = decryptFileBuffer(encryptedPayload);
        const requestedName = sanitizeOriginalFileName(fileRecord.originalName || storedName);

        res.setHeader('Content-Type', fileRecord.mimeType || 'application/octet-stream');
        res.setHeader('Content-Length', String(decryptedPayload.length));
        res.setHeader('Content-Disposition', `inline; filename="${requestedName}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self' data:; sandbox");
        return res.send(decryptedPayload);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return res.status(404).json({ error: 'Media not found.' });
        }

        throw error;
    }
}));

app.get('/', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/projects', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'projects.html'));
});

app.get('/trending', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'trending.html'));
});

app.get('/project', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'project.html'));
});

app.get('/profile', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/admin', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/user', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'user.html'));
});

app.get('/privacy', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/terms', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});

app.all('*', (_req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

async function initializeDatabaseWithRetry() {
    let lastError;

    for (let attempt = 1; attempt <= dbInitRetries; attempt += 1) {
        try {
            await initializeDatabase();
            return;
        } catch (error) {
            lastError = error;
            console.error(`Database initialization failed (attempt ${attempt}/${dbInitRetries}): ${error.message}`);

            if (attempt < dbInitRetries) {
                await sleep(dbInitDelayMs);
            }
        }
    }

    throw lastError;
}

initializeDatabaseWithRetry()
    .then(() => {
        app.listen(port, () => {
            console.log(`Example app listening at http://localhost:${port}`);
        });
    })
    .catch((error) => {
        console.error('Database initialization failed permanently:', error.message);
        process.exit(1);
    });
