let currentUser = null;
let siteSettings = null;
let publicProjectsCache = [];
let profileProjectsCache = [];
let currentNotifications = [];
let adminOverviewCache = {
    users: [],
    projects: [],
    reports: [],
    auditLogs: [],
    inviteCodes: [],
    storage: { users: [], totalBytes: 0, totalFiles: 0 },
    settings: null
};
let currentProjectData = null;
let currentProjectComments = [];
let currentPublicUserProfile = null;
let editableProjectDownloadables = [];
let editableProjectScreenshots = [];
let removedDownloadableKeys = new Set();
let removedScreenshotKeys = new Set();
let pendingTwoFactorSetup = null;
let recaptchaScriptPromise = null;
let registerRecaptchaWidgetId = null;
let pendingExternalUrl = null;

async function apiRequest(url, options = {}) {
    const headers = { ...(options.headers || {}) };
    const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;

    if (!isFormData && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, {
        ...options,
        headers
    });

    const contentType = response.headers.get('content-type') || '';
    let data = {};

    if (contentType.includes('application/json')) {
        data = await response.json().catch(() => ({}));
    } else {
        const text = await response.text().catch(() => '');
        data = text ? { message: text } : {};
    }

    if (!response.ok) {
        const error = new Error(data.error || data.message || 'Request failed.');
        error.payload = data;
        Object.assign(error, data);
        throw error;
    }

    return data;
}

function escapeHtml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatDate(value) {
    if (!value) {
        return '-';
    }

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return '-';
    }

    return date.toLocaleString();
}

function formatBanMessage(user) {
    if (!user || !user.isBanned) {
        return '';
    }

    const parts = ['Your account is banned from using the website while this ban is active.'];
    if (user.banReason) {
        parts.push(`Reason: ${user.banReason}`);
    }
    if (user.banExpiresAt) {
        parts.push(`Ban ends: ${formatDate(user.banExpiresAt)}`);
    }

    return parts.join(' ');
}

function isBannedRestrictedUser() {
    return Boolean(currentUser && currentUser.isBanned);
}

function formatFileSize(value) {
    const bytes = Number(value) || 0;
    if (!bytes) {
        return '0 B';
    }

    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    if (bytes < 1024 * 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function serializeTimelineEntries(entries = [], fallbackTitle = 'Entry') {
    return entries.map((entry) => {
        const title = String(entry?.title || fallbackTitle).trim();
        const body = String(entry?.body || '').trim();
        return body ? `${title} | ${body}` : title;
    }).join('\n');
}

function serializeExternalLinkEntries(entries = []) {
    return entries.map((entry) => {
        const label = String(entry?.label || '').trim();
        const url = String(entry?.url || '').trim();
        if (!url) {
            return '';
        }
        return label ? `${label} | ${url}` : url;
    }).filter(Boolean).join('\n');
}

function getProjectOwnerUserIds(project) {
    return new Set((project?.owners || [])
        .map((owner) => owner?.userId)
        .filter(Boolean));
}

function renderBadgeChips(container, badges = []) {
    if (!container) {
        return;
    }

    if (!badges.length) {
        container.innerHTML = '';
        container.hidden = true;
        return;
    }

    container.hidden = false;
    container.innerHTML = badges.map((badge) => `<span class="status-chip status-chip-muted">${escapeHtml(badge.label || badge)}</span>`).join('');
}

function getSearchParam(name) {
    return new URLSearchParams(window.location.search).get(name);
}

function setTheme(theme) {
    const nextTheme = theme === 'dark' ? 'dark' : 'light';
    document.body.classList.toggle('dark-mode', nextTheme === 'dark');
    document.body.classList.toggle('light-mode', nextTheme === 'light');
    localStorage.setItem('quarky-theme', nextTheme);
    const toggleButton = document.getElementById('mode-toggle');
    if (toggleButton) {
        toggleButton.textContent = nextTheme === 'dark' ? 'Light' : 'Mode';
    }
}

function updateThemeToggle() {
    setTheme(localStorage.getItem('quarky-theme') || 'light');
    const toggleButton = document.getElementById('mode-toggle');
    if (!toggleButton) {
        return;
    }

    toggleButton.addEventListener('click', () => {
        setTheme(document.body.classList.contains('dark-mode') ? 'light' : 'dark');
    });
}

function setNavigation(user) {
    document.querySelectorAll('#auth-link').forEach((link) => {
        if (user) {
            link.href = '/profile';
            link.textContent = user.username;
        } else {
            link.href = '/login';
            link.textContent = 'Login';
        }
    });

    document.querySelectorAll('#admin-link').forEach((link) => {
        const isAdmin = Boolean(user && user.role === 'admin');
        link.hidden = !isAdmin;
        link.classList.toggle('nav-hidden', !isAdmin);
    });
}

function renderAnnouncementBanner() {
    const banner = document.getElementById('announcement-banner');
    if (!banner) {
        return;
    }

    if (!siteSettings || !siteSettings.announcementEnabled || !siteSettings.announcementText) {
        banner.hidden = true;
        banner.innerHTML = '';
        return;
    }

    const link = siteSettings.announcementLink
        ? `<a href="${escapeHtml(siteSettings.announcementLink)}">Read more</a>`
        : '';
    banner.hidden = false;
    banner.innerHTML = `
        <strong>Update:</strong> ${escapeHtml(siteSettings.announcementText)}
        ${link}
    `;
}

async function loadPublicSettings() {
    try {
        const data = await apiRequest('/api/site-settings');
        siteSettings = data.settings || null;
    } catch (error) {
        siteSettings = null;
    }
}

function resetRegisterRecaptcha() {
    if (registerRecaptchaWidgetId != null && window.grecaptcha) {
        window.grecaptcha.reset(registerRecaptchaWidgetId);
    }
}

function loadRecaptchaScript() {
    if (window.grecaptcha) {
        return Promise.resolve(window.grecaptcha);
    }

    if (recaptchaScriptPromise) {
        return recaptchaScriptPromise;
    }

    recaptchaScriptPromise = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://www.google.com/recaptcha/api.js?render=explicit';
        script.async = true;
        script.defer = true;
        script.onload = () => {
            if (window.grecaptcha) {
                resolve(window.grecaptcha);
            } else {
                reject(new Error('Captcha loaded incorrectly. Refresh and try again.'));
            }
        };
        script.onerror = () => reject(new Error('Captcha could not be loaded right now. Refresh and try again.'));
        document.head.appendChild(script);
    });

    return recaptchaScriptPromise;
}

async function ensureRegisterRecaptcha() {
    const shell = document.getElementById('register-captcha-shell');
    const slot = document.getElementById('register-captcha');
    if (!shell || !slot) {
        return;
    }

    if (!siteSettings || !siteSettings.recaptchaEnabled || !siteSettings.recaptchaSiteKey) {
        shell.hidden = true;
        return;
    }

    shell.hidden = false;

    if (registerRecaptchaWidgetId != null && window.grecaptcha) {
        return;
    }

    const grecaptcha = await loadRecaptchaScript();
    await new Promise((resolve) => grecaptcha.ready(resolve));

    registerRecaptchaWidgetId = grecaptcha.render('register-captcha', {
        sitekey: siteSettings.recaptchaSiteKey,
        theme: document.body.classList.contains('dark-mode') ? 'dark' : 'light'
    });
}

async function loadCurrentUser() {
    try {
        const data = await apiRequest('/api/me');
        currentUser = data.user || null;
        profileProjectsCache = data.projects || [];
        currentNotifications = data.notifications || [];
        siteSettings = data.settings || siteSettings;
    } catch (error) {
        currentUser = null;
        currentNotifications = [];
    }
}

function enforceBannedPageRestriction() {
    if (!isBannedRestrictedUser()) {
        return false;
    }

    if (window.location.pathname !== '/profile') {
        window.location.href = '/profile';
        return true;
    }

    return false;
}

function updateLoginRegisterHelpers() {
    const loginHelper = document.getElementById('login-helper');
    const registerHelper = document.getElementById('register-helper');

    if (loginHelper) {
        if (siteSettings && !siteSettings.registrationsEnabled) {
            loginHelper.textContent = 'Registration is currently unavailable.';
        } else if (siteSettings && siteSettings.inviteOnlyEnabled) {
            loginHelper.innerHTML = 'Need an account? Registration is invite-only right now.';
        } else {
            loginHelper.innerHTML = 'Need an account? <a id="register-link" href="/register">Register</a>';
        }
    }

    if (registerHelper) {
        if (siteSettings && siteSettings.approvalRequired) {
            registerHelper.innerHTML = 'Already registered? <a href="/login">Login</a>. New accounts also need approval before first use.';
        } else {
            registerHelper.innerHTML = 'Already registered? <a href="/login">Login</a>';
        }
    }
}

function renderProjectCard(project, options = {}) {
    const owners = (project.owners && project.owners.length ? project.owners : [{
        userId: project.ownerUserId,
        username: project.owner || 'Deleted User'
    }]).map((owner) => owner.userId
        ? `<a class="text-link" href="/user?id=${encodeURIComponent(owner.userId)}">${escapeHtml(owner.username || 'Deleted User')}</a>`
        : escapeHtml(owner.username || 'Deleted User'));
    const ownerLine = owners.join(', ');
    const preview = project.screenshots && project.screenshots[0]
        ? `<a class="gallery-item" href="/project?id=${encodeURIComponent(project.id)}"><img class="gallery-image" src="${escapeHtml(project.screenshots[0].url)}" alt="${escapeHtml(project.title)}"></a>`
        : '';
    const tags = (project.tags || []).slice(0, 5).map((tag) => `<span class="tag-chip">#${escapeHtml(tag)}</span>`).join('');
    const stats = `
        <div class="card-stats">
            <span class="card-stat">${escapeHtml(project.visibility)}</span>
            <span class="card-stat">${escapeHtml(project.likeCount)} favorites</span>
            <span class="card-stat">${escapeHtml(project.commentCount)} comments</span>
            <span class="card-stat">${escapeHtml(project.downloadCount)} downloads</span>
        </div>
    `;
    const actions = options.actions || `<a class="btn" href="/project?id=${encodeURIComponent(project.id)}">Open Project</a>`;

    return `
        <article class="project-card">
            ${preview}
            <p class="card-kicker">${escapeHtml(project.type || 'Project')}</p>
            <h2>${escapeHtml(project.title)}</h2>
            <p>${escapeHtml(project.summary || 'No summary yet.')}</p>
            ${tags ? `<div class="chip-row">${tags}</div>` : ''}
            ${stats}
            <p class="meta-line">By ${ownerLine}</p>
            <div class="button-row">${actions}</div>
        </article>
    `;
}

function renderProjectCollection(container, projects, emptyText, options = {}) {
    if (!container) {
        return;
    }

    if (!projects.length) {
        container.innerHTML = `<p class="helper-text">${escapeHtml(emptyText)}</p>`;
        return;
    }

    container.innerHTML = projects.map((project) => renderProjectCard(project, typeof options === 'function' ? options(project) : options)).join('');
}

function renderStatCards(stats) {
    const container = document.getElementById('home-stats');
    if (!container) {
        return;
    }

    const entries = [
        ['Total Users', stats.totalUsers],
        ['Public Projects', stats.totalProjects],
        ['Total Downloads', stats.totalDownloads],
        ['Total Views', stats.totalViews]
    ];

    container.innerHTML = entries.map(([label, value]) => `
        <article class="stat-card">
            <span>${escapeHtml(label)}</span>
            <strong>${escapeHtml(value)}</strong>
        </article>
    `).join('');
}

function renderLatestUploads(uploads) {
    const container = document.getElementById('home-uploads');
    if (!container) {
        return;
    }

    if (!uploads.length) {
        container.innerHTML = '<p class="helper-text">No public uploads yet.</p>';
        return;
    }

    container.innerHTML = uploads.map((upload) => `
        <article class="upload-card">
            <strong>${escapeHtml(upload.originalName || 'Upload')}</strong>
            <p>${escapeHtml(formatFileSize(upload.size))}</p>
            <p>From <a class="text-link" href="/project?id=${encodeURIComponent(upload.projectId)}">${escapeHtml(upload.projectTitle || 'Project')}</a></p>
            <p>By ${upload.ownerUserId ? `<a class="text-link" href="/user?id=${encodeURIComponent(upload.ownerUserId)}">${escapeHtml(upload.owner || 'Deleted User')}</a>` : escapeHtml(upload.owner || 'Deleted User')}</p>
        </article>
    `).join('');
}

function renderNewestProjects(projects) {
    const container = document.getElementById('home-newest');
    if (!container) {
        return;
    }

    if (!projects.length) {
        container.innerHTML = '<p class="helper-text">No public projects yet.</p>';
        return;
    }

    container.innerHTML = projects.map((project) => `
        <article class="project-mini-card panel-soft">
            <strong>${escapeHtml(project.title)}</strong>
            <p class="meta-line">${escapeHtml(project.summary || 'No summary yet.')}</p>
            <div class="button-row">
                <a class="text-link" href="/project?id=${encodeURIComponent(project.id)}">Open</a>
                ${project.ownerUserId ? `<a class="text-link" href="/user?id=${encodeURIComponent(project.ownerUserId)}">${escapeHtml(project.owner || 'Deleted User')}</a>` : ''}
            </div>
        </article>
    `).join('');
}

function renderTrendingProjects(projects) {
    const container = document.getElementById('home-trending') || document.getElementById('trending-list');
    if (!container) {
        return;
    }

    if (!projects.length) {
        container.innerHTML = '<p class="helper-text">Nothing is trending yet.</p>';
        return;
    }

    container.innerHTML = projects.map((project, index) => `
        <article class="project-mini-card panel-soft trending-card">
            <div class="trending-rank">#${index + 1}</div>
            <strong>${escapeHtml(project.title)}</strong>
            <p class="meta-line">${escapeHtml(project.summary || 'No summary yet.')}</p>
            <div class="chip-row">
                <span class="tag-chip">${escapeHtml(project.downloadCount || 0)} downloads</span>
                <span class="tag-chip">${escapeHtml(project.likeCount || 0)} favorites</span>
                <span class="tag-chip">${escapeHtml(project.commentCount || 0)} comments</span>
            </div>
            <div class="button-row">
                <a class="text-link" href="/project?id=${encodeURIComponent(project.id)}">Open</a>
                ${project.owners && project.owners[0]?.userId ? `<a class="text-link" href="/user?id=${encodeURIComponent(project.owners[0].userId)}">${escapeHtml(project.owners[0].username)}</a>` : ''}
            </div>
        </article>
    `).join('');
}

function renderFollowedFeed(projects) {
    const container = document.getElementById('home-followed-feed');
    if (!container) {
        return;
    }

    if (!currentUser) {
        container.innerHTML = '<p class="helper-text">Log in to get a feed from creators you follow.</p>';
        return;
    }

    if (!projects.length) {
        container.innerHTML = '<p class="helper-text">Follow a few creators and their updates will show up here.</p>';
        return;
    }

    renderProjectCollection(container, projects, 'Nothing from followed creators yet.');
}

async function loadHomePage() {
    if (!document.getElementById('home-featured')) {
        return;
    }

    try {
        const data = await apiRequest('/api/home');
        renderStatCards(data.stats || {});
        renderProjectCollection(document.getElementById('home-featured'), data.featuredProjects || [], 'No featured projects have been chosen yet.');
        renderNewestProjects(data.newestProjects || []);
        renderLatestUploads(data.latestUploads || []);
        renderTrendingProjects(data.trendingProjects || []);
        renderFollowedFeed(data.followedFeed || []);
    } catch (error) {
        document.getElementById('home-featured').innerHTML = `<p class="helper-text">${escapeHtml(error.message)}</p>`;
    }
}

async function loadTrendingPage() {
    if (!document.getElementById('trending-list')) {
        return;
    }

    try {
        const data = await apiRequest('/api/trending');
        renderTrendingProjects(data.projects || []);
    } catch (error) {
        document.getElementById('trending-list').innerHTML = `<p class="helper-text">${escapeHtml(error.message)}</p>`;
    }
}

function populateProjectFilters(projects) {
    const categorySelect = document.getElementById('projects-category');
    const tagSelect = document.getElementById('projects-tag');
    if (!categorySelect || !tagSelect) {
        return;
    }

    const categories = [...new Set(projects.map((project) => String(project.type || '').trim()).filter(Boolean))].sort();
    const tags = [...new Set(projects.flatMap((project) => project.tags || []))].sort();

    categorySelect.innerHTML = '<option value="">All categories</option>' + categories
        .map((entry) => `<option value="${escapeHtml(entry.toLowerCase())}">${escapeHtml(entry)}</option>`)
        .join('');
    tagSelect.innerHTML = '<option value="">All tags</option>' + tags
        .map((entry) => `<option value="${escapeHtml(entry)}">${escapeHtml(entry)}</option>`)
        .join('');
}

function applyProjectFilters() {
    const container = document.getElementById('projects-list');
    if (!container) {
        return;
    }

    const search = String(document.getElementById('projects-search')?.value || '').trim().toLowerCase();
    const category = String(document.getElementById('projects-category')?.value || '').trim().toLowerCase();
    const tag = String(document.getElementById('projects-tag')?.value || '').trim().toLowerCase();
    const featuredOnly = Boolean(document.getElementById('projects-featured')?.checked);

    const filtered = publicProjectsCache.filter((project) => {
        if (featuredOnly && !project.featured) {
            return false;
        }

        if (category && String(project.type || '').trim().toLowerCase() !== category) {
            return false;
        }

        if (tag && !(project.tags || []).includes(tag)) {
            return false;
        }

        if (!search) {
            return true;
        }

        return [
            project.title,
            project.summary,
            project.description,
            project.owner,
            ...((project.owners || []).map((owner) => owner.username)),
            project.type,
            ...(project.tags || [])
        ].some((value) => String(value || '').toLowerCase().includes(search));
    });

    renderProjectCollection(container, filtered, 'No projects match the current filters.');

    const summary = document.getElementById('projects-filter-summary');
    if (summary) {
        summary.textContent = `Showing ${filtered.length} of ${publicProjectsCache.length} public projects.`;
    }
}

function attachProjectFilters() {
    const searchInput = document.getElementById('projects-search');
    const categorySelect = document.getElementById('projects-category');
    const tagSelect = document.getElementById('projects-tag');
    const featuredToggle = document.getElementById('projects-featured');

    searchInput?.addEventListener('input', applyProjectFilters);
    categorySelect?.addEventListener('change', applyProjectFilters);
    tagSelect?.addEventListener('change', applyProjectFilters);
    featuredToggle?.addEventListener('change', applyProjectFilters);
}

async function loadProjectsPage() {
    if (!document.getElementById('projects-list')) {
        return;
    }

    try {
        attachProjectFilters();
        const data = await apiRequest('/api/projects');
        publicProjectsCache = data.projects || [];
        populateProjectFilters(publicProjectsCache);
        applyProjectFilters();
    } catch (error) {
        document.getElementById('projects-list').innerHTML = `<p class="helper-text">${escapeHtml(error.message)}</p>`;
    }
}

function renderProjectTags(tags) {
    const container = document.getElementById('project-tags');
    if (!container) {
        return;
    }

    if (!tags.length) {
        container.innerHTML = '';
        return;
    }

    container.innerHTML = tags.map((tag) => `<span class="tag-chip">#${escapeHtml(tag)}</span>`).join('');
}

function renderProjectOwners(owners) {
    const list = document.getElementById('project-owner-list');
    const badges = document.getElementById('project-owner-badges');
    if (!list || !badges) {
        return;
    }

    if (!owners.length) {
        list.innerHTML = '';
        badges.innerHTML = '';
        return;
    }

    list.innerHTML = owners.map((owner) => owner.userId
        ? `<a class="status-chip status-chip-muted" href="/user?id=${encodeURIComponent(owner.userId)}">${escapeHtml(owner.username)}${owner.isPrimary ? ' · lead' : ''}</a>`
        : `<span class="status-chip status-chip-muted">${escapeHtml(owner.username)}${owner.isPrimary ? ' · lead' : ''}</span>`
    ).join('');

    const teamText = owners.length > 1 ? `Team project · ${owners.length} owners` : 'Solo project';
    badges.innerHTML = `<span class="status-chip status-chip-muted">${escapeHtml(teamText)}</span>`;
}

function renderProjectDownloads(downloadables) {
    const list = document.getElementById('project-downloads');
    if (!list) {
        return;
    }

    if (!downloadables.length) {
        list.innerHTML = '<li class="helper-text">No files added yet.</li>';
        return;
    }

    list.innerHTML = downloadables.map((entry) => `
        <li class="download-item">
            <div>
                <strong>${escapeHtml(entry.name || 'Download')}</strong>
                <p class="meta-line">${escapeHtml(formatFileSize(entry.size))}</p>
            </div>
            <a class="btn btn-secondary" href="${escapeHtml(entry.url)}" download="${escapeHtml(entry.name || 'download')}">Download</a>
        </li>
    `).join('');
}

function renderProjectScreenshots(screenshots) {
    const container = document.getElementById('project-screenshots');
    if (!container) {
        return;
    }

    if (!screenshots.length) {
        container.innerHTML = '<p class="helper-text">No screenshots uploaded yet.</p>';
        return;
    }

    container.innerHTML = screenshots.map((entry) => `
        <a class="gallery-item" href="${escapeHtml(entry.url)}" target="_blank" rel="noopener noreferrer">
            <img class="gallery-image" src="${escapeHtml(entry.url)}" alt="${escapeHtml(entry.name || 'Project screenshot')}">
        </a>
    `).join('');
}

function renderProjectChangelog(changelog) {
    const container = document.getElementById('project-changelog');
    if (!container) {
        return;
    }

    if (!changelog.length) {
        container.innerHTML = '<p class="helper-text">No updates posted yet.</p>';
        return;
    }

    container.innerHTML = changelog.map((entry) => `
        <article class="audit-item">
            <strong>${escapeHtml(entry.title || 'Update')}</strong>
            <p class="meta-line">${escapeHtml(formatDate(entry.createdAt))}</p>
            ${entry.body ? `<p>${escapeHtml(entry.body)}</p>` : ''}
        </article>
    `).join('');
}

function renderProjectDevlogs(devlogs) {
    const container = document.getElementById('project-devlogs');
    if (!container) {
        return;
    }

    if (!devlogs.length) {
        container.innerHTML = '<p class="helper-text">No devlogs posted yet.</p>';
        return;
    }

    container.innerHTML = devlogs.map((entry) => `
        <article class="audit-item">
            <strong>${escapeHtml(entry.title || 'Devlog')}</strong>
            <p class="meta-line">${escapeHtml(formatDate(entry.createdAt))}</p>
            ${entry.body ? `<p>${escapeHtml(entry.body)}</p>` : ''}
        </article>
    `).join('');
}

function renderKnownBugs(knownBugs) {
    const container = document.getElementById('project-known-bugs');
    if (!container) {
        return;
    }

    if (!knownBugs.length) {
        container.innerHTML = '<p class="helper-text">No known bugs are listed right now.</p>';
        return;
    }

    container.innerHTML = knownBugs.map((entry) => `
        <article class="audit-item">
            <div class="button-row">
                <strong>${escapeHtml(entry.title || 'Known issue')}</strong>
                <span class="status-pill ${entry.status === 'fixed' ? 'pill-success' : 'pill-danger'}">${escapeHtml(entry.status || 'open')}</span>
            </div>
            ${entry.body ? `<p>${escapeHtml(entry.body)}</p>` : ''}
        </article>
    `).join('');
}

function renderExternalLinks(links) {
    const container = document.getElementById('project-external-links');
    if (!container) {
        return;
    }

    if (!links.length) {
        container.innerHTML = '<p class="helper-text">No external links added.</p>';
        return;
    }

    container.innerHTML = links.map((entry) => `
        <article class="storage-row external-link-card">
            <div>
                <strong>${escapeHtml(entry.label || entry.hostname || 'External link')}</strong>
                <p class="meta-line">${escapeHtml(entry.hostname || entry.url)}</p>
            </div>
            <button class="btn btn-secondary" type="button" data-external-url="${escapeHtml(entry.url)}" data-external-label="${escapeHtml(entry.label || entry.hostname || 'external site')}">Open</button>
        </article>
    `).join('');
}

function renderProjectOwners(owners) {
    const list = document.getElementById('project-owner-list');
    const badges = document.getElementById('project-owner-badges');
    if (!list || !badges) {
        return;
    }

    if (!owners.length) {
        list.innerHTML = '';
        badges.innerHTML = '';
        return;
    }

    list.innerHTML = owners.map((owner) => owner.userId
        ? `<a class="status-chip status-chip-muted" href="/user?id=${encodeURIComponent(owner.userId)}">${escapeHtml(owner.username)}${owner.isPrimary ? ' · lead' : ''}</a>`
        : `<span class="status-chip status-chip-muted">${escapeHtml(owner.username)}${owner.isPrimary ? ' · lead' : ''}</span>`
    ).join('');

    const leadOwner = owners.find((owner) => owner.isPrimary) || owners[0];
    const chips = [
        owners.length > 1 ? `Team project · ${owners.length} owners` : 'Solo project',
        leadOwner ? `Lead: ${leadOwner.username}` : ''
    ].filter(Boolean);

    badges.innerHTML = chips.map((chip) => `<span class="status-chip status-chip-muted">${escapeHtml(chip)}</span>`).join('');
}

function openExternalLinkPrompt(url, label = 'external site') {
    if (!url) {
        return;
    }

    const dialog = document.getElementById('external-link-dialog');
    const message = document.getElementById('external-link-message');
    if (!dialog || typeof dialog.showModal !== 'function') {
        const confirmed = window.confirm(`Open ${label} in a new tab?`);
        if (confirmed) {
            window.open(url, '_blank', 'noopener,noreferrer');
        }
        return;
    }

    pendingExternalUrl = url;
    message.textContent = `You are about to open ${label}. This link will open in a new tab.`;
    dialog.showModal();
}

function commentCanBeDeleted(comment) {
    if (!currentUser || !currentProjectData) {
        return false;
    }

    const ownerIds = getProjectOwnerUserIds(currentProjectData.project);
    return currentUser.role === 'admin'
        || currentUser.userId === comment.authorUserId
        || ownerIds.has(currentUser.userId);
}

function renderProjectComments(comments) {
    const container = document.getElementById('project-comments');
    if (!container) {
        return;
    }

    if (!comments.length) {
        container.innerHTML = '<p class="helper-text">No comments yet. Be the first one to leave feedback.</p>';
        return;
    }

    container.innerHTML = comments.map((comment) => `
        <article class="comment-item">
            <div class="comment-item-header">
                <div class="profile-mini">
                    ${comment.authorAvatarMedia ? `<img class="avatar avatar-sm" src="${escapeHtml(comment.authorAvatarMedia.url)}" alt="${escapeHtml(comment.author)}">` : ''}
                    <div>
                        <strong>${escapeHtml(comment.author || 'Deleted User')}</strong>
                        <p class="meta-line">${escapeHtml(formatDate(comment.createdAt))}</p>
                    </div>
                </div>
                <div class="button-row">
                    ${comment.isHidden ? '<span class="status-pill pill-danger">Hidden</span>' : ''}
                    <button class="btn btn-secondary" type="button" data-comment-action="report" data-comment-id="${escapeHtml(comment.id)}">Report</button>
                    ${commentCanBeDeleted(comment) ? `<button class="btn btn-danger" type="button" data-comment-action="delete" data-comment-id="${escapeHtml(comment.id)}">Delete</button>` : ''}
                </div>
            </div>
            <p class="comment-content">${escapeHtml(comment.content)}</p>
        </article>
    `).join('');
}

async function refreshProjectComments(projectId) {
    const data = await apiRequest(`/api/projects/${encodeURIComponent(projectId)}/comments`);
    currentProjectComments = data.comments || [];
    renderProjectComments(currentProjectComments);
}

function setProjectTab(target) {
    document.querySelectorAll('.tab-button').forEach((button) => {
        button.classList.toggle('active', button.getAttribute('data-tab-target') === target);
    });

    document.querySelectorAll('.tab-panel').forEach((panel) => {
        panel.classList.toggle('active', panel.getAttribute('data-tab-panel') === target);
    });
}

async function loadProjectPage() {
    const title = document.getElementById('project-title');
    if (!title) {
        return;
    }

    const projectId = getSearchParam('id');
    if (!projectId) {
        title.textContent = 'Project not found';
        return;
    }

    try {
        const data = await apiRequest(`/api/projects/${encodeURIComponent(projectId)}`);
        currentProjectData = data;
        const project = data.project;
        const owners = Array.isArray(project.owners) ? project.owners : [];
        const leadOwner = owners.find((owner) => owner.isPrimary) || owners[0] || null;

        document.title = `Quarky - ${project.title}`;
        title.textContent = project.title;
        document.getElementById('project-summary').textContent = project.summary || 'No summary yet.';
        document.getElementById('project-description').textContent = project.description || 'No description yet.';
        document.getElementById('project-type').textContent = project.type || 'Project';
        document.getElementById('project-status').textContent = project.status || '-';
        document.getElementById('project-visibility').textContent = project.visibility || '-';
        document.getElementById('project-owner').textContent = leadOwner?.username || project.owner || '-';
        document.getElementById('project-owner-link').href = leadOwner?.userId ? `/user?id=${encodeURIComponent(leadOwner.userId)}` : (project.ownerUserId ? `/user?id=${encodeURIComponent(project.ownerUserId)}` : '/projects');
        document.getElementById('project-view-count').textContent = project.viewCount || 0;
        document.getElementById('project-download-count').textContent = project.downloadCount || 0;
        document.getElementById('project-like-count').textContent = project.likeCount || 0;
        document.getElementById('project-comment-count').textContent = project.commentCount || 0;
        document.getElementById('project-created').textContent = formatDate(project.createdAt);
        document.getElementById('project-updated').textContent = formatDate(project.updatedAt);
        document.getElementById('project-like-button').textContent = data.likedByViewer ? 'Favorited' : 'Favorite';
        document.getElementById('project-like-button').classList.toggle('btn', true);
        document.getElementById('project-like-button').classList.toggle('btn-secondary', !data.likedByViewer);
        renderProjectTags(project.tags || []);
        renderProjectOwners(owners);
        renderProjectDownloads(project.downloadables || []);
        renderProjectScreenshots(project.screenshots || []);
        renderProjectChangelog(project.changelog || []);
        renderProjectDevlogs(project.devlogs || []);
        renderKnownBugs(project.knownBugs || []);
        renderExternalLinks(project.externalLinks || []);

        const ownerAvatar = document.getElementById('project-owner-avatar');
        const avatarMedia = leadOwner?.avatarMedia || project.ownerAvatarMedia;
        if (avatarMedia) {
            ownerAvatar.hidden = false;
            ownerAvatar.src = avatarMedia.url;
            ownerAvatar.alt = leadOwner?.username || project.owner || 'Project owner';
        } else {
            ownerAvatar.hidden = true;
            ownerAvatar.removeAttribute('src');
        }

        const editLink = document.getElementById('project-edit-link');
        if (data.canEdit) {
            editLink.hidden = false;
        } else {
            editLink.hidden = true;
        }

        const commentForm = document.getElementById('comment-form');
        const commentMessage = document.getElementById('comment-message');
        if (!currentUser) {
            commentForm.querySelectorAll('textarea, button').forEach((field) => {
                field.disabled = true;
            });
            commentMessage.textContent = 'Log in to leave a comment or favorite this project.';
        } else {
            commentForm.querySelectorAll('textarea, button').forEach((field) => {
                field.disabled = false;
            });
            commentMessage.textContent = '';
        }

        await refreshProjectComments(project.id);
    } catch (error) {
        title.textContent = 'Project not found';
        document.getElementById('project-summary').textContent = error.message;
        document.getElementById('project-description').textContent = 'This project could not be loaded.';
    }
}

function promptForReport() {
    const reason = window.prompt('Reason? Try broken file, copyright, misleading, unsafe, or other.', 'other');
    if (reason === null) {
        return null;
    }

    const details = window.prompt('Extra details (optional).', '') ?? '';
    return { reason, details };
}

function attachProjectPage() {
    if (!document.getElementById('project-title')) {
        return;
    }

    const externalDialog = document.getElementById('external-link-dialog');
    externalDialog?.addEventListener('close', () => {
        pendingExternalUrl = null;
    });
    document.getElementById('external-link-confirm')?.addEventListener('click', () => {
        const url = pendingExternalUrl;
        pendingExternalUrl = null;
        externalDialog?.close('confirm');
        if (url) {
            window.open(url, '_blank', 'noopener,noreferrer');
        }
    });

    document.getElementById('external-link-cancel')?.addEventListener('click', () => {
        pendingExternalUrl = null;
    });

    document.querySelectorAll('.tab-button').forEach((button) => {
        button.addEventListener('click', () => {
            setProjectTab(button.getAttribute('data-tab-target'));
        });
    });

    const likeButton = document.getElementById('project-like-button');
    likeButton?.addEventListener('click', async () => {
        if (!currentProjectData) {
            return;
        }

        if (!currentUser) {
            window.location.href = '/login';
            return;
        }

        try {
            const data = await apiRequest(`/api/projects/${encodeURIComponent(currentProjectData.project.id)}/like`, {
                method: 'POST'
            });
            currentProjectData.project = data.project;
            currentProjectData.likedByViewer = data.liked;
            document.getElementById('project-like-count').textContent = data.project.likeCount || 0;
            document.getElementById('project-like-button').textContent = data.liked ? 'Favorited' : 'Favorite';
        } catch (error) {
            document.getElementById('comment-message').textContent = error.message;
        }
    });

    document.getElementById('project-report-button')?.addEventListener('click', async () => {
        if (!currentProjectData) {
            return;
        }

        if (!currentUser) {
            window.location.href = '/login';
            return;
        }

        const report = promptForReport();
        if (!report) {
            return;
        }

        try {
            await apiRequest(`/api/projects/${encodeURIComponent(currentProjectData.project.id)}/report`, {
                method: 'POST',
                body: JSON.stringify(report)
            });
            document.getElementById('comment-message').textContent = 'Thanks, your report was sent.';
        } catch (error) {
            document.getElementById('comment-message').textContent = error.message;
        }
    });

    document.getElementById('comment-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!currentProjectData) {
            return;
        }

        const message = document.getElementById('comment-message');
        const content = document.getElementById('comment-content').value.trim();
        if (!content) {
            message.textContent = 'Write a comment before posting.';
            return;
        }

        try {
            await apiRequest(`/api/projects/${encodeURIComponent(currentProjectData.project.id)}/comments`, {
                method: 'POST',
                body: JSON.stringify({ content })
            });
            document.getElementById('comment-content').value = '';
            message.textContent = 'Comment posted.';
            await refreshProjectComments(currentProjectData.project.id);
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('project-comments')?.addEventListener('click', async (event) => {
        const button = event.target.closest('[data-comment-action]');
        if (!button || !currentProjectData) {
            return;
        }

        const commentId = button.getAttribute('data-comment-id');
        const action = button.getAttribute('data-comment-action');
        const message = document.getElementById('comment-message');

        try {
            if (action === 'delete') {
                const confirmed = window.confirm('Delete this comment?');
                if (!confirmed) {
                    return;
                }

                await apiRequest(`/api/comments/${encodeURIComponent(commentId)}`, {
                    method: 'DELETE'
                });
                message.textContent = 'Comment deleted.';
            }

            if (action === 'report') {
                if (!currentUser) {
                    window.location.href = '/login';
                    return;
                }

                const report = promptForReport();
                if (!report) {
                    return;
                }

                await apiRequest(`/api/comments/${encodeURIComponent(commentId)}/report`, {
                    method: 'POST',
                    body: JSON.stringify(report)
                });
                message.textContent = 'Thanks, your report was sent.';
            }

            await refreshProjectComments(currentProjectData.project.id);
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('project-external-links')?.addEventListener('click', (event) => {
        const button = event.target.closest('[data-external-url]');
        if (!button) {
            return;
        }

        openExternalLinkPrompt(
            button.getAttribute('data-external-url'),
            button.getAttribute('data-external-label') || 'external site'
        );
    });
}

function resetTwoFactorUi() {
    pendingTwoFactorSetup = null;
    document.getElementById('two-factor-setup-box')?.setAttribute('hidden', 'hidden');
    document.getElementById('two-factor-backup-box')?.setAttribute('hidden', 'hidden');
    const backupCodes = document.getElementById('two-factor-backup-codes');
    if (backupCodes) {
        backupCodes.textContent = '';
    }
}

function renderTwoFactorState() {
    const enabled = Boolean(currentUser && currentUser.twoFactorEnabled);
    const locked = Boolean(currentUser && currentUser.isBanned);
    const statusLine = document.getElementById('two-factor-status');
    const settingValue = document.getElementById('settings-two-factor');
    const startButton = document.getElementById('two-factor-start-button');
    const disableForm = document.getElementById('two-factor-disable-form');

    if (!statusLine || !settingValue || !startButton || !disableForm) {
        return;
    }

    settingValue.textContent = enabled ? 'Enabled' : 'Disabled';
    statusLine.textContent = locked
        ? formatBanMessage(currentUser)
        : (enabled
            ? 'Two-factor authentication is enabled for this account.'
            : 'Two-factor authentication is currently disabled.');
    startButton.hidden = enabled;
    disableForm.hidden = !enabled;
    startButton.disabled = locked;
    disableForm.querySelectorAll('input, button').forEach((field) => {
        field.disabled = locked;
    });
}

function getDownloadableKey(entry) {
    return entry ? (entry.storedName || entry.url || entry.name || '') : '';
}

function renderEditableEntryList(containerId, entries, removedSet, emptyText, typeLabel) {
    const container = document.getElementById(containerId);
    if (!container) {
        return;
    }

    if (!entries.length) {
        container.innerHTML = `<p class="helper-text">${escapeHtml(emptyText)}</p>`;
        return;
    }

    container.innerHTML = entries.map((entry) => {
        const key = getDownloadableKey(entry);
        const checked = removedSet.has(key) ? 'checked' : '';
        return `
            <label class="toggle-line">
                <input type="checkbox" data-remove-key="${escapeHtml(key)}" ${checked}>
                <span>Remove ${escapeHtml(entry.name || typeLabel)} (${escapeHtml(formatFileSize(entry.size))})</span>
            </label>
        `;
    }).join('');
}

function renderProfileHeader() {
    document.getElementById('profile-display-username').textContent = currentUser.username;
    document.getElementById('profile-display-bio').textContent = currentUser.bio || 'Add a short bio so people know what you build.';
    document.getElementById('profile-role-chip').textContent = currentUser.role;
    document.getElementById('profile-project-count-chip').textContent = `${profileProjectsCache.length} project${profileProjectsCache.length === 1 ? '' : 's'}`;
    document.getElementById('profile-followers-chip').textContent = `${currentUser.followerCount || 0} followers`;
    document.getElementById('profile-following-chip').textContent = `${currentUser.followingCount || 0} following`;
    renderBadgeChips(document.getElementById('profile-badges'), currentUser.badges || []);
    document.getElementById('profile-force-reset').hidden = !currentUser.forcePasswordReset;
    document.getElementById('profile-force-reset').textContent = currentUser.forcePasswordReset
        ? 'You need to change your password before using the rest of the site.'
        : '';
    const profileMessage = document.getElementById('profile-message');
    if (profileMessage) {
        profileMessage.textContent = currentUser.isBanned ? formatBanMessage(currentUser) : '';
    }

    const avatar = document.getElementById('profile-avatar-display');
    if (currentUser.avatarMedia) {
        avatar.hidden = false;
        avatar.src = currentUser.avatarMedia.url;
        avatar.alt = `${currentUser.username} avatar`;
    } else {
        avatar.hidden = true;
        avatar.removeAttribute('src');
    }

    const banner = document.getElementById('profile-banner-display');
    if (currentUser.bannerMedia) {
        banner.hidden = false;
        banner.src = currentUser.bannerMedia.url;
        banner.alt = `${currentUser.username} banner`;
    } else {
        banner.hidden = true;
        banner.removeAttribute('src');
    }
}

function applyProfileSecurityState() {
    const profileForm = document.getElementById('profile-form');
    if (!profileForm || !currentUser) {
        return;
    }

    const locked = Boolean(currentUser.forcePasswordReset || currentUser.isBanned);
    profileForm.querySelectorAll('input, textarea, button').forEach((field) => {
        field.disabled = locked;
    });

    const message = document.getElementById('profile-form-message');
    if (message && locked) {
        message.textContent = currentUser.isBanned
            ? formatBanMessage(currentUser)
            : 'Change your password first to unlock profile edits.';
    }
}

function renderNotifications() {
    const container = document.getElementById('notifications-list');
    if (!container) {
        return;
    }

    if (!currentNotifications.length) {
        container.innerHTML = '<p class="helper-text">No notifications yet.</p>';
        return;
    }

    container.innerHTML = currentNotifications.map((notification) => `
        <article class="notification-item ${notification.isRead ? '' : 'unread'}">
            <strong>${escapeHtml(notification.message)}</strong>
            <p class="notification-time">${escapeHtml(formatDate(notification.createdAt))}</p>
            ${notification.link ? `<a class="text-link" href="${escapeHtml(notification.link)}">Open</a>` : ''}
        </article>
    `).join('');
}

function renderProfileProjects() {
    if (isBannedRestrictedUser()) {
        const container = document.getElementById('profile-projects');
        if (container) {
            container.innerHTML = `<p class="helper-text">${escapeHtml(formatBanMessage(currentUser))}</p>`;
        }
        return;
    }

    renderProjectCollection(
        document.getElementById('profile-projects'),
        profileProjectsCache,
        'You have not created any projects yet.',
        (project) => ({
            actions: `
                <a class="btn" href="/project?id=${encodeURIComponent(project.id)}">Open</a>
                <button class="btn btn-secondary" type="button" data-project-action="edit" data-project-id="${escapeHtml(project.id)}">Edit</button>
                <button class="btn btn-danger" type="button" data-project-action="delete" data-project-id="${escapeHtml(project.id)}">Delete</button>
            `
        })
    );
}

function applyProjectFormState() {
    const form = document.getElementById('project-form');
    if (!form || !siteSettings || !currentUser) {
        return;
    }

    const message = document.getElementById('project-upload-summary');
    const isEditing = Boolean(document.getElementById('project-id').value.trim());
    const isAdmin = currentUser.role === 'admin';
    const passwordResetLocked = Boolean(currentUser.forcePasswordReset);
    const bannedLocked = Boolean(currentUser.isBanned);
    const limitReached = !isAdmin
        && siteSettings.projectLimitEnabled
        && !isEditing
        && profileProjectsCache.length >= siteSettings.maxProjectsPerUser;
    const creationDisabled = !siteSettings.uploadsEnabled && !isEditing;

    form.querySelectorAll('input, textarea, select, button').forEach((field) => {
        if (field.id === 'cancel-edit-button') {
            field.disabled = false;
            return;
        }
        if (field.id === 'project-files-input' || field.id === 'project-screenshots-input') {
            field.disabled = !siteSettings.uploadsEnabled || passwordResetLocked || bannedLocked;
            return;
        }
        field.disabled = creationDisabled || limitReached || passwordResetLocked || bannedLocked;
    });

    const featuredWrap = document.getElementById('project-featured-wrap');
    if (featuredWrap) {
        featuredWrap.hidden = !isAdmin;
    }

    const notes = [];
    if (creationDisabled) {
        notes.push('File uploads are disabled right now, so creating new projects is also disabled.');
    }
    if (siteSettings.projectLimitEnabled && !isAdmin) {
        notes.push(`Project limit: ${profileProjectsCache.length}/${siteSettings.maxProjectsPerUser}.`);
    }
    if (limitReached) {
        notes.push('You have reached the current project limit.');
    }
    if (siteSettings.uploadSizeLimitEnabled && !isAdmin) {
        notes.push(`Max file size per upload: ${siteSettings.maxUploadSizeMb} MB.`);
    }
    if (isAdmin && (siteSettings.projectLimitEnabled || siteSettings.uploadSizeLimitEnabled)) {
        notes.push('Admin accounts ignore project and upload size limits.');
    }
    if (!siteSettings.uploadsEnabled && isEditing) {
        notes.push('Uploads are disabled, but you can still edit text and remove existing files.');
    }
    if (passwordResetLocked) {
        notes.push('Change your password before editing or creating projects.');
    }
    if (bannedLocked) {
        notes.push(formatBanMessage(currentUser));
    }

    message.textContent = notes.join(' ');
}

function resetProjectForm() {
    const form = document.getElementById('project-form');
    if (!form) {
        return;
    }

    form.reset();
    document.getElementById('project-id').value = '';
    document.getElementById('project-form-title').textContent = 'Create Project';
    document.getElementById('project-form-message').textContent = '';
    editableProjectDownloadables = [];
    editableProjectScreenshots = [];
    removedDownloadableKeys = new Set();
    removedScreenshotKeys = new Set();
    renderEditableEntryList('existing-project-files', editableProjectDownloadables, removedDownloadableKeys, 'No files added to this project yet.', 'attachment');
    renderEditableEntryList('existing-project-screenshots', editableProjectScreenshots, removedScreenshotKeys, 'No screenshots added to this project yet.', 'screenshot');
    applyProjectFormState();
}

function fillProjectForm(project) {
    document.getElementById('project-id').value = project.id;
    document.getElementById('project-name').value = project.title || '';
    document.getElementById('project-summary-input').value = project.summary || '';
    document.getElementById('project-description-input').value = project.description || '';
    document.getElementById('project-type-input').value = project.type || '';
    document.getElementById('project-status-input').value = project.status || '';
    document.getElementById('project-visibility-input').value = project.visibility || 'public';
    document.getElementById('project-owners-input').value = (project.owners || [])
        .filter((owner) => !owner.isPrimary && owner.userId !== currentUser?.userId)
        .map((owner) => owner.username)
        .join('\n');
    document.getElementById('project-tags-input').value = (project.tags || []).join(', ');
    document.getElementById('project-devlogs-input').value = serializeTimelineEntries(project.devlogs || [], 'Devlog');
    document.getElementById('project-changelog-input').value = (project.changelog || [])
        .map((entry) => `${entry.title || 'Update'}${entry.body ? ` | ${entry.body}` : ''}`)
        .join('\n');
    document.getElementById('project-known-bugs-input').value = serializeTimelineEntries(project.knownBugs || [], 'Known issue');
    document.getElementById('project-external-links-input').value = serializeExternalLinkEntries(project.externalLinks || []);
    document.getElementById('project-featured-input').checked = Boolean(project.featured);
    document.getElementById('project-files-input').value = '';
    document.getElementById('project-screenshots-input').value = '';
    editableProjectDownloadables = [...(project.downloadables || [])];
    editableProjectScreenshots = [...(project.screenshots || [])];
    removedDownloadableKeys = new Set();
    removedScreenshotKeys = new Set();
    document.getElementById('project-form-title').textContent = `Edit ${project.title}`;
    renderEditableEntryList('existing-project-files', editableProjectDownloadables, removedDownloadableKeys, 'No files added to this project yet.', 'attachment');
    renderEditableEntryList('existing-project-screenshots', editableProjectScreenshots, removedScreenshotKeys, 'No screenshots added to this project yet.', 'screenshot');
    applyProjectFormState();
}

function buildProjectFormData() {
    const formData = new FormData();
    formData.append('title', document.getElementById('project-name').value.trim());
    formData.append('summary', document.getElementById('project-summary-input').value.trim());
    formData.append('description', document.getElementById('project-description-input').value.trim());
    formData.append('type', document.getElementById('project-type-input').value.trim());
    formData.append('status', document.getElementById('project-status-input').value.trim());
    formData.append('visibility', document.getElementById('project-visibility-input').value);
    formData.append('owners', document.getElementById('project-owners-input').value.trim());
    formData.append('tags', document.getElementById('project-tags-input').value.trim());
    formData.append('devlogs', document.getElementById('project-devlogs-input').value.trim());
    formData.append('changelog', document.getElementById('project-changelog-input').value.trim());
    formData.append('knownBugs', document.getElementById('project-known-bugs-input').value.trim());
    formData.append('externalLinks', document.getElementById('project-external-links-input').value.trim());
    formData.append('featured', document.getElementById('project-featured-input').checked ? 'true' : 'false');
    formData.append('removedFiles', JSON.stringify([...removedDownloadableKeys]));
    formData.append('removedScreenshots', JSON.stringify([...removedScreenshotKeys]));

    [...(document.getElementById('project-files-input').files || [])].forEach((file) => {
        formData.append('projectFiles', file);
    });

    [...(document.getElementById('project-screenshots-input').files || [])].forEach((file) => {
        formData.append('projectScreenshots', file);
    });

    return formData;
}

async function refreshProfileData() {
    const data = await apiRequest('/api/me');
    currentUser = data.user;
    profileProjectsCache = data.projects || [];
    currentNotifications = data.notifications || [];
    siteSettings = data.settings || siteSettings;
    setNavigation(currentUser);
    renderAnnouncementBanner();
    renderProfileHeader();
    renderNotifications();
    renderProfileProjects();
    renderTwoFactorState();
    applyProfileSecurityState();
    applyProjectFormState();

    document.getElementById('settings-user-id').textContent = currentUser.userId;
    document.getElementById('settings-username').textContent = currentUser.username;
    document.getElementById('settings-email').textContent = currentUser.email;
    document.getElementById('settings-role').textContent = currentUser.role;
    document.getElementById('settings-two-factor').textContent = currentUser.twoFactorEnabled ? 'Enabled' : 'Disabled';
    document.getElementById('profile-bio-input').value = currentUser.bio || '';
    const markReadButton = document.getElementById('notifications-mark-read');
    if (markReadButton) {
        markReadButton.disabled = Boolean(currentUser.isBanned);
    }
}

function attachProfilePage() {
    if (!document.getElementById('profile-display-username')) {
        return;
    }

    if (!currentUser) {
        window.location.href = '/login';
        return;
    }

    refreshProfileData().catch(() => {
        window.location.href = '/login';
    });

    document.getElementById('profile-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const message = document.getElementById('profile-form-message');
        const formData = new FormData();
        formData.append('bio', document.getElementById('profile-bio-input').value.trim());
        formData.append('removeAvatar', document.getElementById('profile-remove-avatar').checked ? 'true' : 'false');
        formData.append('removeBanner', document.getElementById('profile-remove-banner').checked ? 'true' : 'false');

        const avatarFile = document.getElementById('profile-avatar-file').files[0];
        const bannerFile = document.getElementById('profile-banner-file').files[0];
        if (avatarFile) {
            formData.append('avatarFile', avatarFile);
        }
        if (bannerFile) {
            formData.append('bannerFile', bannerFile);
        }

        try {
            await apiRequest('/api/profile', {
                method: 'PATCH',
                body: formData
            });
            message.textContent = 'Profile updated.';
            document.getElementById('profile-avatar-file').value = '';
            document.getElementById('profile-banner-file').value = '';
            document.getElementById('profile-remove-avatar').checked = false;
            document.getElementById('profile-remove-banner').checked = false;
            await refreshProfileData();
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('password-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const message = document.getElementById('password-message');
        try {
            const data = await apiRequest('/api/profile/password', {
                method: 'POST',
                body: JSON.stringify({
                    currentPassword: document.getElementById('current-password-input').value,
                    newPassword: document.getElementById('new-password-input').value
                })
            });
            currentUser = data.user || currentUser;
            document.getElementById('password-form').reset();
            message.textContent = 'Password updated.';
            await refreshProfileData();
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('notifications-mark-read')?.addEventListener('click', async () => {
        if (currentUser?.isBanned) {
            document.getElementById('profile-message').textContent = formatBanMessage(currentUser);
            return;
        }

        try {
            await apiRequest('/api/me/notifications/read', { method: 'POST' });
            currentNotifications = currentNotifications.map((entry) => ({ ...entry, isRead: true }));
            renderNotifications();
        } catch (error) {
            document.getElementById('profile-message').textContent = error.message;
        }
    });

    document.getElementById('project-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (currentUser?.isBanned) {
            document.getElementById('project-form-message').textContent = formatBanMessage(currentUser);
            return;
        }

        const projectId = document.getElementById('project-id').value.trim();
        const message = document.getElementById('project-form-message');
        const payload = buildProjectFormData();

        try {
            if (projectId) {
                await apiRequest(`/api/projects/${encodeURIComponent(projectId)}`, {
                    method: 'PUT',
                    body: payload
                });
                message.textContent = 'Project updated.';
            } else {
                await apiRequest('/api/projects', {
                    method: 'POST',
                    body: payload
                });
                message.textContent = 'Project created.';
            }

            resetProjectForm();
            await refreshProfileData();
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('cancel-edit-button')?.addEventListener('click', () => {
        resetProjectForm();
    });

    document.getElementById('existing-project-files')?.addEventListener('change', (event) => {
        const checkbox = event.target.closest('[data-remove-key]');
        if (!checkbox) {
            return;
        }
        const key = checkbox.getAttribute('data-remove-key');
        if (checkbox.checked) {
            removedDownloadableKeys.add(key);
        } else {
            removedDownloadableKeys.delete(key);
        }
    });

    document.getElementById('existing-project-screenshots')?.addEventListener('change', (event) => {
        const checkbox = event.target.closest('[data-remove-key]');
        if (!checkbox) {
            return;
        }
        const key = checkbox.getAttribute('data-remove-key');
        if (checkbox.checked) {
            removedScreenshotKeys.add(key);
        } else {
            removedScreenshotKeys.delete(key);
        }
    });

    document.getElementById('profile-projects')?.addEventListener('click', async (event) => {
        if (currentUser?.isBanned) {
            document.getElementById('profile-message').textContent = formatBanMessage(currentUser);
            return;
        }

        const actionButton = event.target.closest('[data-project-action]');
        if (!actionButton) {
            return;
        }

        const projectId = actionButton.getAttribute('data-project-id');
        const action = actionButton.getAttribute('data-project-action');
        const project = profileProjectsCache.find((entry) => entry.id === projectId);
        if (!project) {
            return;
        }

        if (action === 'edit') {
            fillProjectForm(project);
            window.scrollTo({ top: 0, behavior: 'smooth' });
            return;
        }

        if (action === 'delete') {
            const confirmed = window.confirm(`Delete "${project.title}"?`);
            if (!confirmed) {
                return;
            }

            try {
                await apiRequest(`/api/projects/${encodeURIComponent(project.id)}`, {
                    method: 'DELETE'
                });
                document.getElementById('profile-message').textContent = 'Project deleted.';
                resetProjectForm();
                await refreshProfileData();
            } catch (error) {
                document.getElementById('profile-message').textContent = error.message;
            }
        }
    });

    document.getElementById('logout-button')?.addEventListener('click', async () => {
        try {
            await apiRequest('/api/logout', { method: 'POST' });
            window.location.href = '/login';
        } catch (error) {
            document.getElementById('profile-message').textContent = error.message;
        }
    });

    const twoFactorMessage = document.getElementById('two-factor-message');
    document.getElementById('two-factor-start-button')?.addEventListener('click', async () => {
        try {
            const data = await apiRequest('/api/profile/2fa/setup', { method: 'POST' });
            pendingTwoFactorSetup = data;
            document.getElementById('two-factor-secret').textContent = data.manualEntryKey;
            document.getElementById('two-factor-otpauth').href = data.otpAuthUrl;
            document.getElementById('two-factor-setup-box').hidden = false;
            document.getElementById('two-factor-backup-box').hidden = true;
            twoFactorMessage.textContent = 'Add the secret to your authenticator app, then confirm the first code.';
            renderTwoFactorState();
        } catch (error) {
            twoFactorMessage.textContent = error.message;
        }
    });

    document.getElementById('two-factor-enable-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        try {
            const data = await apiRequest('/api/profile/2fa/enable', {
                method: 'POST',
                body: JSON.stringify({
                    token: document.getElementById('two-factor-enable-token').value.trim()
                })
            });
            currentUser.twoFactorEnabled = true;
            pendingTwoFactorSetup = null;
            document.getElementById('two-factor-setup-box').hidden = true;
            document.getElementById('two-factor-backup-box').hidden = false;
            document.getElementById('two-factor-backup-codes').textContent = (data.backupCodes || []).join('\n');
            twoFactorMessage.textContent = 'Two-factor authentication is enabled. Save your backup codes now.';
            renderTwoFactorState();
        } catch (error) {
            twoFactorMessage.textContent = error.message;
        }
    });

    document.getElementById('two-factor-disable-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        try {
            await apiRequest('/api/profile/2fa/disable', {
                method: 'POST',
                body: JSON.stringify({
                    password: document.getElementById('two-factor-disable-password').value,
                    token: document.getElementById('two-factor-disable-token').value.trim()
                })
            });
            currentUser.twoFactorEnabled = false;
            resetTwoFactorUi();
            twoFactorMessage.textContent = 'Two-factor authentication has been disabled.';
            renderTwoFactorState();
        } catch (error) {
            twoFactorMessage.textContent = error.message;
        }
    });
}

function renderAdminSettings(settings) {
    document.getElementById('settings-registrations-enabled').checked = settings.registrationsEnabled;
    document.getElementById('settings-login-enabled').checked = settings.loginEnabled;
    document.getElementById('settings-invite-only-enabled').checked = settings.inviteOnlyEnabled;
    document.getElementById('settings-approval-required').checked = settings.approvalRequired;
    document.getElementById('settings-uploads-enabled').checked = settings.uploadsEnabled;
    document.getElementById('settings-new-account-restrictions-enabled').checked = settings.newAccountRestrictionsEnabled;
    document.getElementById('settings-new-account-restriction-hours').value = settings.newAccountRestrictionHours;
    document.getElementById('settings-project-limit-enabled').checked = settings.projectLimitEnabled;
    document.getElementById('settings-max-projects').value = settings.maxProjectsPerUser;
    document.getElementById('settings-upload-size-limit-enabled').checked = settings.uploadSizeLimitEnabled;
    document.getElementById('settings-max-upload-size').value = settings.maxUploadSizeMb;
    document.getElementById('settings-trust-level-enabled').checked = Boolean(settings.trustLevelEnabled);
    document.getElementById('settings-low-trust-age-hours').value = settings.lowTrustAgeHours;
    document.getElementById('settings-low-trust-comment-cooldown').value = settings.lowTrustCommentCooldownSeconds;
    document.getElementById('settings-low-trust-project-cooldown').value = settings.lowTrustProjectCooldownMinutes;
    document.getElementById('settings-word-blacklist').value = Array.isArray(settings.wordBlacklist)
        ? settings.wordBlacklist.join('\n')
        : '';

    document.getElementById('settings-new-account-restriction-hours').disabled = !settings.newAccountRestrictionsEnabled;
    document.getElementById('settings-max-projects').disabled = !settings.projectLimitEnabled;
    document.getElementById('settings-max-upload-size').disabled = !settings.uploadSizeLimitEnabled;
    document.getElementById('settings-low-trust-age-hours').disabled = !settings.trustLevelEnabled;
    document.getElementById('settings-low-trust-comment-cooldown').disabled = !settings.trustLevelEnabled;
    document.getElementById('settings-low-trust-project-cooldown').disabled = !settings.trustLevelEnabled;
    document.getElementById('settings-word-blacklist').disabled = !settings.trustLevelEnabled;
}

function renderAnnouncementComposer(settings) {
    const enabled = document.getElementById('settings-announcement-enabled');
    const text = document.getElementById('settings-announcement-text');
    const link = document.getElementById('settings-announcement-link');
    if (!enabled || !text || !link) {
        return;
    }

    enabled.checked = settings.announcementEnabled;
    text.value = settings.announcementText || '';
    link.value = settings.announcementLink || '';
}

function renderAdminUsers(users) {
    const container = document.getElementById('admin-users');
    if (!container) {
        return;
    }

    if (!users.length) {
        container.innerHTML = '<p class="helper-text">No users found.</p>';
        return;
    }

    container.innerHTML = users.map((user) => `
        <article class="user-card">
            <div class="user-card-header">
                <div>
                    <h3>${escapeHtml(user.username)}</h3>
                    <p class="meta-line">${escapeHtml(user.email)}</p>
                </div>
                <span class="status-pill ${user.isBanned ? 'pill-danger' : 'pill-success'}">${user.isBanned ? 'Banned' : user.role}</span>
            </div>
            <p class="meta-line">User ID: ${escapeHtml(user.userId)}</p>
            <p class="meta-line">Projects: ${escapeHtml(user.projectCount)} | Followers: ${escapeHtml(user.followerCount || 0)} | Following: ${escapeHtml(user.followingCount || 0)}</p>
            <p class="meta-line">Approved: ${user.isApproved ? 'Yes' : 'No'}</p>
            <p class="meta-line">2FA: ${user.twoFactorEnabled ? 'Enabled' : 'Disabled'} | Password reset required: ${user.forcePasswordReset ? 'Yes' : 'No'}</p>
            <p class="meta-line">Created: ${escapeHtml(formatDate(user.createdAt))}</p>
            ${user.isBanned ? `<p class="meta-line">Ban reason: ${escapeHtml(user.banReason || 'No reason given')}</p>` : ''}
            ${user.isBanned && user.banExpiresAt ? `<p class="meta-line">Ban ends: ${escapeHtml(formatDate(user.banExpiresAt))}</p>` : ''}
            <div class="button-row">
                <button class="btn btn-secondary" type="button" data-user-action="toggle-ban" data-user-id="${escapeHtml(user.userId)}">${user.isBanned ? 'Unban' : 'Ban'}</button>
                <button class="btn btn-secondary" type="button" data-user-action="toggle-role" data-user-id="${escapeHtml(user.userId)}">${user.role === 'admin' ? 'Make User' : 'Make Admin'}</button>
                <button class="btn btn-secondary" type="button" data-user-action="toggle-approval" data-user-id="${escapeHtml(user.userId)}">${user.isApproved ? 'Set Pending' : 'Approve'}</button>
                <button class="btn btn-secondary" type="button" data-user-action="toggle-force-reset" data-user-id="${escapeHtml(user.userId)}">${user.forcePasswordReset ? 'Clear Reset Flag' : 'Force Password Reset'}</button>
                <button class="btn btn-danger" type="button" data-user-action="delete" data-user-id="${escapeHtml(user.userId)}">Delete</button>
            </div>
        </article>
    `).join('');
}

function renderInviteCodes(inviteCodes) {
    const container = document.getElementById('admin-invites');
    if (!container) {
        return;
    }

    if (!inviteCodes.length) {
        container.innerHTML = '<p class="helper-text">No invite codes created yet.</p>';
        return;
    }

    container.innerHTML = inviteCodes.map((invite) => `
        <article class="storage-row">
            <div>
                <strong>${escapeHtml(invite.code)}</strong>
                <p class="meta-line">Uses left: ${escapeHtml(invite.usesRemaining)} | Created by: ${escapeHtml(invite.createdBy || 'System')}</p>
                <p class="meta-line">Expires: ${invite.expiresAt ? escapeHtml(formatDate(invite.expiresAt)) : 'Never'}</p>
            </div>
            <div class="button-row">
                <button class="btn btn-secondary" type="button" data-invite-action="copy" data-invite-code="${escapeHtml(invite.code)}">Copy</button>
                <button class="btn btn-danger" type="button" data-invite-action="revoke" data-invite-code="${escapeHtml(invite.code)}">Revoke</button>
            </div>
        </article>
    `).join('');
}

function renderAdminProjects(projects) {
    const container = document.getElementById('admin-projects');
    if (!container) {
        return;
    }

    renderProjectCollection(container, projects, 'No projects found.', (project) => ({
        actions: `
            <a class="btn" href="/project?id=${encodeURIComponent(project.id)}">Open</a>
            <button class="btn btn-secondary" type="button" data-admin-project-action="feature" data-project-id="${escapeHtml(project.id)}">${project.featured ? 'Unfeature' : 'Feature'}</button>
            <button class="btn btn-danger" type="button" data-admin-project-action="delete" data-project-id="${escapeHtml(project.id)}">Delete</button>
        `
    }));
}

function renderReports(reports) {
    const container = document.getElementById('admin-reports');
    if (!container) {
        return;
    }

    if (!reports.length) {
        container.innerHTML = '<p class="helper-text">No open or historical reports yet.</p>';
        return;
    }

    container.innerHTML = reports.map((report) => `
        <article class="report-card">
            <div class="user-card-header">
                <div>
                    <strong>${escapeHtml(report.targetType)} report</strong>
                    <p class="meta-line">Reporter: ${escapeHtml(report.reporter || 'Deleted User')} | ${escapeHtml(formatDate(report.createdAt))}</p>
                </div>
                <span class="status-pill">${escapeHtml(report.status)}</span>
            </div>
            <p class="meta-line">Reason: ${escapeHtml(report.reason)}</p>
            ${report.details ? `<p>${escapeHtml(report.details)}</p>` : '<p class="helper-text">No extra details.</p>'}
            <div class="button-row">
                ${report.targetType === 'project' ? `<a class="text-link" href="/project?id=${encodeURIComponent(report.targetId)}">Open target</a>` : ''}
            </div>
            <form class="report-form-grid" data-report-form data-report-id="${escapeHtml(report.id)}">
                <label class="stack-label">
                    <span>Status</span>
                    <select name="status">
                        <option value="open" ${report.status === 'open' ? 'selected' : ''}>Open</option>
                        <option value="reviewing" ${report.status === 'reviewing' ? 'selected' : ''}>Reviewing</option>
                        <option value="actioned" ${report.status === 'actioned' ? 'selected' : ''}>Actioned</option>
                        <option value="dismissed" ${report.status === 'dismissed' ? 'selected' : ''}>Dismissed</option>
                    </select>
                </label>
                <label class="stack-label">
                    <span>Admin note</span>
                    <textarea name="adminNote" rows="3" placeholder="What happened, and what action did you take?">${escapeHtml(report.adminNote || '')}</textarea>
                </label>
                <button class="btn" type="submit">Save Report</button>
            </form>
        </article>
    `).join('');
}

function renderAuditLog(entries) {
    const container = document.getElementById('admin-audit-log');
    if (!container) {
        return;
    }

    if (!entries.length) {
        container.innerHTML = '<p class="helper-text">No audit entries yet.</p>';
        return;
    }

    container.innerHTML = entries.map((entry) => `
        <article class="audit-item">
            <strong>${escapeHtml(entry.action)}</strong>
            <p class="meta-line">${escapeHtml(entry.actor || 'System')} on ${escapeHtml(entry.targetType)} ${entry.targetId ? `(${escapeHtml(entry.targetId)})` : ''}</p>
            ${entry.details ? `<p>${escapeHtml(entry.details)}</p>` : ''}
            <p class="meta-line">${escapeHtml(formatDate(entry.createdAt))}</p>
        </article>
    `).join('');
}

function renderStorageDashboard(storage) {
    const total = document.getElementById('admin-storage-total');
    const container = document.getElementById('admin-storage-users');
    if (!total || !container) {
        return;
    }

    total.textContent = `Total encrypted files: ${storage.totalFiles || 0} | Total storage: ${formatFileSize(storage.totalBytes || 0)}`;

    if (!(storage.users || []).length) {
        container.innerHTML = '<p class="helper-text">No upload storage data yet.</p>';
        return;
    }

    container.innerHTML = (storage.users || []).map((entry) => `
        <article class="storage-row">
            <strong>${escapeHtml(entry.username)}</strong>
            <p>${escapeHtml(formatFileSize(entry.storageBytes))}</p>
            <p class="meta-line">${escapeHtml(entry.fileCount)} file(s)</p>
        </article>
    `).join('');
}

async function refreshAdminOverview() {
    const data = await apiRequest('/api/admin/overview');
    adminOverviewCache = data;
    siteSettings = data.settings || siteSettings;
    renderAnnouncementBanner();
    renderAdminSettings(data.settings);
    renderAnnouncementComposer(data.settings);
    renderAdminUsers(data.users || []);
    renderAdminProjects(data.projects || []);
    renderReports(data.reports || []);
    renderAuditLog(data.auditLogs || []);
    renderStorageDashboard(data.storage || { users: [], totalBytes: 0, totalFiles: 0 });
    renderInviteCodes(data.inviteCodes || []);
}

function attachAdminPage() {
    if (!document.getElementById('admin-users')) {
        return;
    }

    if (!currentUser) {
        window.location.href = '/login';
        return;
    }

    if (currentUser.role !== 'admin') {
        window.location.href = '/profile';
        return;
    }

    refreshAdminOverview().catch((error) => {
        document.getElementById('admin-message').textContent = error.message;
    });

    document.getElementById('admin-settings-form')?.addEventListener('change', (event) => {
        if (event.target.id === 'settings-new-account-restrictions-enabled') {
            document.getElementById('settings-new-account-restriction-hours').disabled = !event.target.checked;
        }

        if (event.target.id === 'settings-project-limit-enabled') {
            document.getElementById('settings-max-projects').disabled = !event.target.checked;
        }

        if (event.target.id === 'settings-upload-size-limit-enabled') {
            document.getElementById('settings-max-upload-size').disabled = !event.target.checked;
        }

        if (event.target.id === 'settings-trust-level-enabled') {
            const disabled = !event.target.checked;
            document.getElementById('settings-low-trust-age-hours').disabled = disabled;
            document.getElementById('settings-low-trust-comment-cooldown').disabled = disabled;
            document.getElementById('settings-low-trust-project-cooldown').disabled = disabled;
            document.getElementById('settings-word-blacklist').disabled = disabled;
        }
    });

    document.getElementById('admin-settings-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const message = document.getElementById('admin-settings-message');
        const payload = {
            registrationsEnabled: document.getElementById('settings-registrations-enabled').checked,
            loginEnabled: document.getElementById('settings-login-enabled').checked,
            inviteOnlyEnabled: document.getElementById('settings-invite-only-enabled').checked,
            approvalRequired: document.getElementById('settings-approval-required').checked,
            uploadsEnabled: document.getElementById('settings-uploads-enabled').checked,
            newAccountRestrictionsEnabled: document.getElementById('settings-new-account-restrictions-enabled').checked,
            newAccountRestrictionHours: document.getElementById('settings-new-account-restriction-hours').value,
            projectLimitEnabled: document.getElementById('settings-project-limit-enabled').checked,
            maxProjectsPerUser: document.getElementById('settings-max-projects').value,
            uploadSizeLimitEnabled: document.getElementById('settings-upload-size-limit-enabled').checked,
            maxUploadSizeMb: document.getElementById('settings-max-upload-size').value,
            trustLevelEnabled: document.getElementById('settings-trust-level-enabled').checked,
            lowTrustAgeHours: document.getElementById('settings-low-trust-age-hours').value,
            lowTrustCommentCooldownSeconds: document.getElementById('settings-low-trust-comment-cooldown').value,
            lowTrustProjectCooldownMinutes: document.getElementById('settings-low-trust-project-cooldown').value,
            wordBlacklist: document.getElementById('settings-word-blacklist').value
        };

        try {
            const data = await apiRequest('/api/admin/settings', {
                method: 'PATCH',
                body: JSON.stringify(payload)
            });
            siteSettings = data.settings || siteSettings;
            renderAnnouncementBanner();
            renderAdminSettings(data.settings);
            message.textContent = 'Settings saved.';
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('admin-invite-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const message = document.getElementById('admin-invite-message');
        try {
            const response = await apiRequest('/api/admin/invites', {
                method: 'POST',
                body: JSON.stringify({
                    usesRemaining: document.getElementById('invite-uses-remaining').value,
                    expiresInDays: document.getElementById('invite-expires-days').value.trim()
                })
            });
            await refreshAdminOverview();
            message.textContent = `Invite code created: ${response.invite.code}`;
            event.target.reset();
            document.getElementById('invite-uses-remaining').value = '1';
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('admin-announcement-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const message = document.getElementById('admin-announcement-message');
        const text = document.getElementById('settings-announcement-text').value.trim();
        const link = document.getElementById('settings-announcement-link').value.trim();
        const enabled = document.getElementById('settings-announcement-enabled').checked;

        if (!text) {
            message.textContent = 'Add a message before sending the announcement.';
            return;
        }

        try {
            const data = await apiRequest('/api/admin/settings', {
                method: 'PATCH',
                body: JSON.stringify({
                    announcementEnabled: enabled || Boolean(text),
                    announcementText: text,
                    announcementLink: link
                })
            });
            siteSettings = data.settings || siteSettings;
            renderAnnouncementBanner();
            renderAnnouncementComposer(data.settings);
            message.textContent = 'Announcement sent.';
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('clear-announcement-button')?.addEventListener('click', async () => {
        const message = document.getElementById('admin-announcement-message');
        try {
            const data = await apiRequest('/api/admin/settings', {
                method: 'PATCH',
                body: JSON.stringify({
                    announcementEnabled: false,
                    announcementText: '',
                    announcementLink: ''
                })
            });
            siteSettings = data.settings || siteSettings;
            renderAnnouncementBanner();
            renderAnnouncementComposer(data.settings);
            message.textContent = 'Announcement cleared.';
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('admin-users')?.addEventListener('click', async (event) => {
        const button = event.target.closest('[data-user-action]');
        if (!button) {
            return;
        }

        const userId = button.getAttribute('data-user-id');
        const action = button.getAttribute('data-user-action');
        const user = (adminOverviewCache.users || []).find((entry) => entry.userId === userId);
        if (!user) {
            return;
        }

        const message = document.getElementById('admin-message');

        try {
            if (action === 'toggle-ban') {
                let payload = { banned: !user.isBanned };
                if (!user.isBanned) {
                    const reason = window.prompt(`Ban reason for ${user.username}?`, user.banReason || '');
                    if (reason === null) {
                        return;
                    }

                    const hoursInput = window.prompt(`How many hours should ${user.username} be banned for? Leave blank for no automatic expiry.`, '');
                    if (hoursInput === null) {
                        return;
                    }

                    const trimmedHours = hoursInput.trim();
                    if (trimmedHours) {
                        const parsedHours = Number(trimmedHours);
                        if (!Number.isFinite(parsedHours) || parsedHours < 1) {
                            message.textContent = 'Ban hours must be a whole number of at least 1.';
                            return;
                        }
                        payload.hours = Math.floor(parsedHours);
                    }

                    payload.reason = reason.trim();
                }

                await apiRequest(`/api/admin/users/${encodeURIComponent(userId)}/ban`, {
                    method: 'PATCH',
                    body: JSON.stringify(payload)
                });
            }

            if (action === 'toggle-role') {
                await apiRequest(`/api/admin/users/${encodeURIComponent(userId)}/role`, {
                    method: 'PATCH',
                    body: JSON.stringify({ role: user.role === 'admin' ? 'user' : 'admin' })
                });
            }

            if (action === 'toggle-approval') {
                await apiRequest(`/api/admin/users/${encodeURIComponent(userId)}/approve`, {
                    method: 'PATCH',
                    body: JSON.stringify({ approved: !user.isApproved })
                });
            }

            if (action === 'toggle-force-reset') {
                await apiRequest(`/api/admin/users/${encodeURIComponent(userId)}/force-reset`, {
                    method: 'PATCH',
                    body: JSON.stringify({ force: !user.forcePasswordReset })
                });
            }

            if (action === 'delete') {
                const confirmed = window.confirm(`Delete user "${user.username}"?`);
                if (!confirmed) {
                    return;
                }

                await apiRequest(`/api/admin/users/${encodeURIComponent(userId)}`, {
                    method: 'DELETE'
                });
            }

            await refreshAdminOverview();
            message.textContent = 'User action saved.';
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('admin-projects')?.addEventListener('click', async (event) => {
        const button = event.target.closest('[data-admin-project-action]');
        if (!button) {
            return;
        }

        const action = button.getAttribute('data-admin-project-action');
        const projectId = button.getAttribute('data-project-id');
        const project = (adminOverviewCache.projects || []).find((entry) => entry.id === projectId);
        if (!project) {
            return;
        }

        try {
            if (action === 'feature') {
                await apiRequest(`/api/admin/projects/${encodeURIComponent(projectId)}/feature`, {
                    method: 'PATCH',
                    body: JSON.stringify({ featured: !project.featured })
                });
            }

            if (action === 'delete') {
                const confirmed = window.confirm(`Delete project "${project.title}"?`);
                if (!confirmed) {
                    return;
                }

                await apiRequest(`/api/admin/projects/${encodeURIComponent(projectId)}`, {
                    method: 'DELETE'
                });
            }

            await refreshAdminOverview();
            document.getElementById('admin-message').textContent = 'Project action saved.';
        } catch (error) {
            document.getElementById('admin-message').textContent = error.message;
        }
    });

    document.getElementById('admin-invites')?.addEventListener('click', async (event) => {
        const button = event.target.closest('[data-invite-action]');
        if (!button) {
            return;
        }

        const inviteCode = button.getAttribute('data-invite-code');
        const action = button.getAttribute('data-invite-action');
        const message = document.getElementById('admin-invite-message');

        try {
            if (action === 'copy') {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(inviteCode);
                    message.textContent = `Copied ${inviteCode}`;
                } else {
                    window.prompt('Copy this invite code:', inviteCode);
                    message.textContent = 'Invite code ready to copy.';
                }
                return;
            }

            if (action === 'revoke') {
                const confirmed = window.confirm(`Revoke invite code "${inviteCode}"?`);
                if (!confirmed) {
                    return;
                }

                await apiRequest(`/api/admin/invites/${encodeURIComponent(inviteCode)}`, {
                    method: 'DELETE'
                });
                await refreshAdminOverview();
                message.textContent = 'Invite code revoked.';
            }
        } catch (error) {
            message.textContent = error.message;
        }
    });

    document.getElementById('admin-reports')?.addEventListener('submit', async (event) => {
        const form = event.target.closest('[data-report-form]');
        if (!form) {
            return;
        }

        event.preventDefault();
        const reportId = form.getAttribute('data-report-id');
        try {
            await apiRequest(`/api/admin/reports/${encodeURIComponent(reportId)}`, {
                method: 'PATCH',
                body: JSON.stringify({
                    status: form.elements.status.value,
                    adminNote: form.elements.adminNote.value.trim()
                })
            });
            await refreshAdminOverview();
            document.getElementById('admin-message').textContent = 'Report updated.';
        } catch (error) {
            document.getElementById('admin-message').textContent = error.message;
        }
    });

    document.getElementById('clear-reports-button')?.addEventListener('click', async () => {
        const confirmed = window.confirm('Clear every report in the queue? This cannot be undone.');
        if (!confirmed) {
            return;
        }

        try {
            const data = await apiRequest('/api/admin/reports', {
                method: 'DELETE'
            });
            await refreshAdminOverview();
            document.getElementById('admin-message').textContent = `${data.count || 0} report(s) cleared.`;
        } catch (error) {
            document.getElementById('admin-message').textContent = error.message;
        }
    });
}

async function loadUserPage() {
    const title = document.getElementById('user-display-username');
    if (!title) {
        return;
    }

    const userId = getSearchParam('id');
    if (!userId) {
        title.textContent = 'User not found';
        return;
    }

    try {
        const data = await apiRequest(`/api/users/${encodeURIComponent(userId)}`);
        currentPublicUserProfile = data;
        const user = data.user;
        title.textContent = user.username;
        document.getElementById('user-display-bio').textContent = user.bio || 'This creator has not added a bio yet.';
        document.getElementById('user-project-count-chip').textContent = `${(data.projects || []).length} public project${(data.projects || []).length === 1 ? '' : 's'}`;
        document.getElementById('user-followers-chip').textContent = `${user.followerCount || 0} followers`;
        document.getElementById('user-following-chip').textContent = `${user.followingCount || 0} following`;
        renderBadgeChips(document.getElementById('user-badges'), user.badges || []);

        const avatar = document.getElementById('user-avatar-display');
        if (user.avatarMedia) {
            avatar.hidden = false;
            avatar.src = user.avatarMedia.url;
            avatar.alt = `${user.username} avatar`;
        } else {
            avatar.hidden = true;
        }

        const banner = document.getElementById('user-banner-display');
        if (user.bannerMedia) {
            banner.hidden = false;
            banner.src = user.bannerMedia.url;
            banner.alt = `${user.username} banner`;
        } else {
            banner.hidden = true;
        }

        const followButton = document.getElementById('user-follow-button');
        if (currentUser && currentUser.userId === user.userId) {
            followButton.hidden = true;
        } else {
            followButton.hidden = false;
            followButton.textContent = data.isFollowing ? 'Following' : 'Follow';
        }

        renderProjectCollection(document.getElementById('user-projects'), data.projects || [], 'No public projects from this user yet.');
    } catch (error) {
        title.textContent = 'User not found';
        document.getElementById('user-display-bio').textContent = error.message;
        document.getElementById('user-follow-button').hidden = true;
    }
}

function attachUserPage() {
    if (!document.getElementById('user-follow-button')) {
        return;
    }

    document.getElementById('user-follow-button').addEventListener('click', async () => {
        if (!currentPublicUserProfile) {
            return;
        }

        if (!currentUser) {
            window.location.href = '/login';
            return;
        }

        try {
            const data = await apiRequest(`/api/users/${encodeURIComponent(currentPublicUserProfile.user.userId)}/follow`, {
                method: 'POST'
            });
            currentPublicUserProfile.isFollowing = data.isFollowing;
            document.getElementById('user-follow-button').textContent = data.isFollowing ? 'Following' : 'Follow';
            document.getElementById('user-followers-chip').textContent = `${data.followerCount || 0} followers`;
            document.getElementById('user-message').textContent = data.isFollowing ? 'You are now following this creator.' : 'You unfollowed this creator.';
        } catch (error) {
            document.getElementById('user-message').textContent = error.message;
        }
    });
}

function attachLoginForm() {
    const form = document.getElementById('login-form');
    if (!form) {
        return;
    }

    const message = document.getElementById('login-message');
    const otpGroup = document.getElementById('login-otp-group');
    const otpInput = document.getElementById('login-otp');
    if (siteSettings && !siteSettings.loginEnabled) {
        message.textContent = 'Login is currently unavailable for this account.';
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const payload = {
            username: document.getElementById('login-username').value.trim(),
            password: document.getElementById('login-password').value,
            otp: otpInput ? otpInput.value.trim() : ''
        };

        try {
            const data = await apiRequest('/api/login', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            if (data.requiresTwoFactor) {
                otpGroup.hidden = false;
                message.textContent = data.message || 'Enter your authenticator code to continue.';
                otpInput?.focus();
                return;
            }

            message.textContent = 'Logged in. Redirecting to your profile.';
            window.location.href = '/profile';
        } catch (error) {
            if (otpGroup && /authenticator|backup code/i.test(error.message)) {
                otpGroup.hidden = false;
            }
            message.textContent = error.message;
        }
    });
}

function attachRegisterForm() {
    const form = document.getElementById('register-form');
    if (!form) {
        return;
    }

    const message = document.getElementById('register-message');
    const inviteGroup = document.getElementById('register-invite-group');
    if (inviteGroup) {
        inviteGroup.hidden = !(siteSettings && siteSettings.inviteOnlyEnabled);
    }
    if (siteSettings && !siteSettings.registrationsEnabled) {
        form.querySelectorAll('input, button').forEach((field) => {
            field.disabled = true;
        });
        message.textContent = 'Registration is currently disabled.';
        return;
    }

    ensureRegisterRecaptcha().catch((error) => {
        message.textContent = error.message;
        form.querySelector('button[type="submit"]')?.setAttribute('disabled', 'disabled');
    });

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        let captchaToken = '';
        if (siteSettings && siteSettings.recaptchaEnabled) {
            captchaToken = window.grecaptcha && registerRecaptchaWidgetId != null
                ? window.grecaptcha.getResponse(registerRecaptchaWidgetId)
                : '';

            if (!captchaToken) {
                message.textContent = 'Complete the captcha check before creating your account.';
                return;
            }
        }

        try {
            const data = await apiRequest('/api/register', {
                method: 'POST',
                body: JSON.stringify({
                    username: document.getElementById('register-username').value.trim(),
                    email: document.getElementById('register-email').value.trim(),
                    password: document.getElementById('register-password').value,
                    inviteCode: document.getElementById('register-invite-code')?.value.trim(),
                    captchaToken
                })
            });
            form.reset();
            if (inviteGroup) {
                inviteGroup.hidden = !(siteSettings && siteSettings.inviteOnlyEnabled);
            }
            resetRegisterRecaptcha();
            message.textContent = data.message || 'Account created.';
        } catch (error) {
            resetRegisterRecaptcha();
            message.textContent = error.message;
        }
    });
}

async function bootstrap() {
    updateThemeToggle();
    await loadPublicSettings();
    await loadCurrentUser();
    setNavigation(currentUser);
    renderAnnouncementBanner();
    if (enforceBannedPageRestriction()) {
        return;
    }
    updateLoginRegisterHelpers();
    attachLoginForm();
    attachRegisterForm();
    await loadHomePage();
    await loadTrendingPage();
    await loadProjectsPage();
    await loadProjectPage();
    attachProjectPage();
    attachProfilePage();
    await loadUserPage();
    attachUserPage();
    attachAdminPage();
}

bootstrap();
