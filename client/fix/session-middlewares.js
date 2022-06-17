"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const logger_1 = __importDefault(require("../logger"));
const uuid_1 = __importDefault(require("uuid"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const CookiePrefix = process.env.COOKIE_PREFIX || "OIDC";
const SessionCookieName = CookiePrefix + "SecureToken";
const UserEmailCookieName = CookiePrefix + "Email";
const ServiceListCookieName = CookiePrefix + "Services";
const CSRFTokenCookieName = "CSRF-Token";
const SessionDetailsPrefix = "SessionDetails-";
const SessionCheckKeyPrefix = "SessionCheck-";
class InvalidSession extends Error {
    constructor(message) {
        super(message);
    }
}
exports.InvalidSession = InvalidSession;
class NotFound extends Error {
    constructor(message) {
        super(message);
    }
}
exports.NotFound = NotFound;
class AlreadyExist extends Error {
    constructor(message) {
        super(message);
    }
}
exports.AlreadyExist = AlreadyExist;
const defaultSessionMwOps = {
    failOnMissing: false,
    loadIntrospect: false,
    loadUserInfo: false
};
function baseUrl(req) {
    return (process.env.EXTERNAL_OWN_URL || req.protocol + "://" + req.headers.host);
    //return req.protocol + "://" + req.headers.host;
}
const defaultSessionDurationMs = 1000 * 60 * 60 * 8; // 8h
function setSessionCookies(res, details) {
    const tokens = details.tokens;
    const now = Date.now();
    const expiresAtMs = tokens.expires_at ? tokens.expires_at * 1000 : (now + defaultSessionDurationMs);
    const durationMs = expiresAtMs - now + 5000;
    //console.log("SET SESSION COOKIES", durationMs, new Date(expiresAtMs))
    if (!details.services) {
        details.services = [];
    }
    else if (!Array.isArray(details.services)) {
        details.services = [details.services.toString()];
    }
    if (!details.services.includes("api")) {
        details.services.push("api");
    }
    if (!details.services.includes("session")) {
        details.services.push("session");
    }
    res.cookie(ServiceListCookieName, details.services.join(":"), {
        httpOnly: true,
        maxAge: durationMs,
        path: "/session"
    });
    details.services.forEach(svc => {
        res.cookie(SessionCookieName, tokens.access_token, {
            httpOnly: true,
            maxAge: durationMs,
            path: "/" + svc.toLowerCase()
        });
    });
    // TODO: need to be removed and replaced by path only cookie ?
    // res.cookie(SessionCookieName, tokens.access_token, {
    //   httpOnly: true,
    //   maxAge: durationMs,
    //   path: "/"
    // });
    if (details.email) {
        res.cookie(UserEmailCookieName, details.email, {
            path: "/",
            httpOnly: true,
            // no expiry on this one
            maxAge: 1000 * 60 * 60 * 24 * 360 * 10 // 10 years
        });
    }
    if (!details.jti) {
        res.cookie(CSRFTokenCookieName, details.jti, {
            path: "/",
            httpOnly: false,
            maxAge: durationMs
        });
    }
}
function clearSessionCookies(req, res) {
    let serviceList = [];
    try {
        serviceList = req.cookies[ServiceListCookieName].split(":");
    }
    catch (error) {
        logger_1.default.error("Invalid cookie format, expected : separated strings", {
            name: ServiceListCookieName,
            value: req.cookies[ServiceListCookieName]
        });
    }
    res.clearCookie(ServiceListCookieName, {
        path: "/session"
    });
    serviceList.forEach(svc => {
        res.clearCookie(SessionCookieName, {
            path: "/" + svc.toLowerCase()
        });
    });
    res.clearCookie(SessionCookieName, {
        path: "/"
    });
    res.clearCookie(CSRFTokenCookieName, {
        path: "/"
    });
}
class SessionMgmt {
    constructor(oidcClientGetter, cache, servicesGetter) {
        this.oidcClientGetter = (req) => __awaiter(this, void 0, void 0, function* () {
            const client = yield oidcClientGetter(req);
            if (client) {
                return client;
            }
            throw new Error("Configuration is not defined");
        });
        this.cache = cache;
        if (servicesGetter) {
            this.getServices = servicesGetter;
        }
        else {
            this.getServices = (ir) => Promise.resolve([]);
        }
        if (process.env.ACCEPTED_REDIRECT_URIS) {
            this.acceptedRedirectUris = process.env.ACCEPTED_REDIRECT_URIS.split(";");
        }
        else {
            if (!process.env.EXTERNAL_OWN_URL) {
                throw new Error("Expected definition of EXTERNAL_OWN_URL env var to default ACCEPTED_REDIRECT_URIS");
            }
            else {
                this.acceptedRedirectUris = [process.env.EXTERNAL_OWN_URL + "*"];
            }
        }
    }
    ;
    getAccessToken(req) {
        const token = req.cookies[SessionCookieName];
        if (token) {
            return token;
        }
        else {
            return undefined;
        }
    }
    validateRedirectUri(redirectUri) {
        const foundAt = this.acceptedRedirectUris.findIndex(uri => {
            if (uri.toLowerCase().startsWith("http")) {
                if (uri.endsWith("*")) {
                    return redirectUri.startsWith(uri.substr(0, uri.length - 1));
                }
                else {
                    return uri == redirectUri;
                }
            }
            else {
                try {
                    const re = new RegExp(uri);
                    return re.test(redirectUri);
                }
                catch (error) {
                    logger_1.default.warn("Invalid RedEx string", {
                        message: error.message,
                        uri: uri
                    });
                    return false;
                }
            }
        });
        // found if index not -1
        return foundAt >= 0;
    }
    clearSessionCache(accessToken) {
        return __awaiter(this, void 0, void 0, function* () {
            if (accessToken) {
                //console.log("CLEAR SESSION CACHE", SessionDetailsPrefix + accessToken)
                return yield this.cache.del(SessionDetailsPrefix + accessToken);
            }
            else {
                return false;
            }
        });
    }
    saveSessionCache(details, previousAccessToken) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.clearSessionCache(previousAccessToken);
            if (!details.expiresAt) {
                details.expiresAt = (details.tokens.expires_at || (Date.now() + defaultSessionDurationMs) / 1000) * 1000;
            }
            const duration = Math.round((details.expiresAt - Date.now()) / 1000);
            if (details.tokens.access_token) {
                //console.log("SAVE SESSION CACHE", SessionDetailsPrefix + details.tokens.access_token, duration, new Date(details.expiresAt))
                return yield this.cache.put(SessionDetailsPrefix + details.tokens.access_token, Object.assign({}, details), // force copying the data
                duration);
            }
            else {
                return false;
            }
        });
    }
    updateDetailsFromIDToken(accessToken, details) {
        return __awaiter(this, void 0, void 0, function* () {
            const idToken = details.tokens.id_token;
            if (!idToken) {
                throw new InvalidSession("Missing id_token in session");
            }
            //    logger.debug("idToken: ", { idToken })
            details.idTokenDecoded = jsonwebtoken_1.default.decode(idToken, { json: true });
            if (!details.idTokenDecoded.authorizations) {
                details.idTokenDecoded.authorizations = [];
            }
            details.services = yield this.getServices(details.idTokenDecoded);
            details.email = details.idTokenDecoded.email;
            details.jti = details.idTokenDecoded.jti || "missing-jti-" + uuid_1.default();
        });
    }
    getSessionDetails(oidcCient, accessToken, needIntrospect = false) {
        return __awaiter(this, void 0, void 0, function* () {
            const details = yield this.cache.get(SessionDetailsPrefix + accessToken);
            if (!details || !details.tokens) {
                logger_1.default.error("Missing a session", { sessionDetails: details });
                throw new InvalidSession("Missing a session");
            }
            if (!details.idTokenDecoded && needIntrospect) {
                yield this.updateDetailsFromIDToken(accessToken, details);
                details.config = oidcCient.config;
                yield this.saveSessionCache(details);
            }
            //console.log("getSessionDetails:", JSON.stringify(details, null, 2))
            return details;
        });
    }
    saveSessionCheckInfo(key, data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (key && data) {
                return yield this.cache.put(SessionCheckKeyPrefix + key, data, 10 * 60);
            }
            else {
                return false;
            }
        });
    }
    getRedirectUri(req) {
        let redirectUri = req.query.redirect_uri || req.headers.referer || baseUrl(req);
        if (redirectUri.startsWith("/")) {
            redirectUri = baseUrl(req) + redirectUri;
        }
        return redirectUri;
    }
    getRegisterMw() {
        return this.getLoginMw(true);
    }
    getLoginMw(register = false) {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            const redirectUri = this.getRedirectUri(req);
            if (!this.validateRedirectUri(redirectUri)) {
                return next("The requested redirectUri is not accepted: " + redirectUri);
            }
            try {
                const oidcClient = yield this.oidcClientGetter(req);
                // start by clearing an existing session if any
                this.clearSessionCache(this.getAccessToken(req));
                // clear the cookies anyway before starting the authentication process
                clearSessionCookies(req, res);
                const checks = {
                    nonce: "N-" + Math.random(),
                    state: uuid_1.default()
                };
                yield this.saveSessionCheckInfo(checks.state, {
                    checks,
                    redirectUri: redirectUri
                });
                let uri = oidcClient.authorizationUrl({
                    nonce: checks.nonce,
                    state: checks.state,
                    login_hint: req.query.email || req.cookies[UserEmailCookieName],
                    prompt: req.query.prompt,
                    scope: oidcClient.metadata.default_scope || "openid"
                });
                if (register) {
                    uri = uri.replace("/auth?", "/registrations?");
                }
                logger_1.default.debug("Authentication with url", { url: uri });
                res.redirect(uri);
                next();
            }
            catch (error) {
                logger_1.default.error("Failed trying to initiate a login", {
                    message: error.message,
                    fullError: error
                });
                next(error);
            }
        });
    }
    getLogoutMw() {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            const token = this.getAccessToken(req);
            const oidcClient = yield this.oidcClientGetter(req);
            const details = yield this.getSessionDetails(oidcClient, token, true);
            const id_token_hint = details.tokens.id_token;
            yield this.clearSessionCache(token);
            try {
                res.redirect((yield this.oidcClientGetter(req)).endSessionUrl({"id_token_hint":id_token_hint}));
            }
            catch (error) {
                return this.getPostLogoutMw()(req, res, next);
            }
            // cookies are cleared on PostLogout
            next();
        });
    }
    getPostLogoutMw() {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            clearSessionCookies(req, res);
            res.redirect(process.env.POST_LOGOUT_URL || "/"); // TODO define a landing page post logout
            next();
        });
    }
    getUserInfoMw() {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            try {
                const token = this.getAccessToken(req);
                if (token) {
                    try {
                        const userInfo = yield (yield this.oidcClientGetter(req)).userinfo(token);
                        res.json(userInfo);
                    }
                    catch (error) {
                        res.json({
                            error: "fail getting user info",
                            details: error
                        });
                    }
                }
                else {
                    res.json({ // empty result
                    });
                }
                next();
            }
            catch (error) {
                logger_1.default.error("Fails getting all tokens", {
                    message: error.message,
                    fullError: error
                });
                next(error);
            }
        });
    }
    getTokensMw() {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            try {
                const token = this.getAccessToken(req);
                const oidcClient = yield this.oidcClientGetter(req);
                if (token) {
                    const details = yield this.getSessionDetails(oidcClient, token, true);
                    let decodedIdToken;
                    let decodedAccessToken;
                    let decodedRefreshToken;
                    try {
                        decodedIdToken = jsonwebtoken_1.default.decode(details.tokens.id_token, { complete: true, json: true });
                    }
                    catch (error) {
                        decodedIdToken = {
                            error: "Fail to parse the ID Token",
                            details: error
                        };
                    }
                    try {
                        decodedAccessToken = yield oidcClient.introspect(details.tokens.access_token);
                    }
                    catch (error) {
                        console.error("Fail to call introspect endpoint for access token", error);
                        decodedAccessToken = {
                            error: "Fail to call introspect endpoint for access token",
                            details: error.message || error.toString()
                        };
                    }
                    try {
                        if (details.tokens.refresh_token)
                            decodedRefreshToken = yield oidcClient.introspect(details.tokens.refresh_token);
                        else
                            decodedRefreshToken = undefined;
                    }
                    catch (error) {
                        decodedRefreshToken = {
                            error: "Fail to call introspect endpoint for refresh token",
                            details: error.message || error.toString()
                        };
                    }
                    res.json({
                        accessToken: details.tokens.access_token,
                        idToken: details.tokens.id_token,
                        refreshToken: details.tokens.refresh_token,
                        decoded: {
                            accessToken: decodedAccessToken,
                            idToken: decodedIdToken,
                            refreshToken: decodedRefreshToken
                        }
                    });
                }
                else {
                    res.json({ // empty result
                    });
                }
                next();
            }
            catch (error) {
                logger_1.default.error("Fails getting all tokens", {
                    message: error.message,
                    fullError: error
                });
                next(error);
            }
        });
    }
    getStateMw() {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            try {
                const token = this.getAccessToken(req);
                const oidcClient = yield this.oidcClientGetter(req);
                if (token) {
                    const details = yield this.getSessionDetails(oidcClient, token, true);
                    const expiresAt = details.expiresAt || Date.now() + defaultSessionDurationMs;
                    let expiresInMs = expiresAt - Date.now();
                    if (expiresInMs < 0) {
                        expiresInMs = 0;
                    }
                    res.json(Object.assign(Object.assign({ config: details.config, active: true }, details), { expiresAt: expiresAt, expiresInMs: expiresInMs, cookies: req.cookies }));
                }
                else {
                    res.json({
                        active: false,
                        email: req.cookies[UserEmailCookieName]
                    });
                }
                next();
            }
            catch (error) {
                logger_1.default.error("Fails getting session state", {
                    message: error.message,
                    fullError: error
                });
                next(error);
            }
        });
    }
    getCodeAuthFlowCallbackMw() {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            try {
                const oidcClient = yield this.oidcClientGetter(req);
                // get and clear the one time check data for the callback
                const data = yield this.cache.get(SessionCheckKeyPrefix + req.query.state);
                yield this.cache.del(SessionCheckKeyPrefix + req.query.state);
                if (!data) {
                    // when the login process took too long to process the SesionCheckData is lost in the cache so login must be restarted
                    logger_1.default.info("Session check data expired so retry to login");
                    return this.getLoginMw(false)(req, res, next);
                }
                logger_1.default.debug("Callback params:", {
                    redirectUri: baseUrl(req) + req.baseUrl + req.path,
                    params: (yield this.oidcClientGetter(req)).callbackParams(req),
                    checks: data.checks
                });
                // retrieve the session from code
                const tokens = yield oidcClient.callback(baseUrl(req) + req.baseUrl + req.path, oidcClient.callbackParams(req), data.checks);
                yield this.saveSessionCache({ tokens }, this.getAccessToken(req));
                // set the cookies
                if (tokens.access_token) {
                    const details = yield this.getSessionDetails(oidcClient, tokens.access_token, true);
                    setSessionCookies(res, details);
                }
                res.redirect(data.redirectUri);
            }
            catch (error) {
                console.error(error);
                logger_1.default.error("Fails getting tokens", {
                    message: error.message,
                    fullError: error
                });
                next(error);
            }
            next();
        });
    }
    refreshSession(oidcClient, accessToken) {
        return __awaiter(this, void 0, void 0, function* () {
            const details = yield this.getSessionDetails(oidcClient, accessToken, true);
            if (details.tokens.refresh_token) {
                const tokens = yield oidcClient.refresh(details.tokens.refresh_token);
                logger_1.default.debug("Refresh tokens:", tokens);
                if (!tokens.refresh_token) {
                    // set the initial refresh token
                    tokens.refresh_token = details.tokens.refresh_token;
                }
                yield this.saveSessionCache({ tokens }, accessToken);
                return tokens;
            }
            else {
                return undefined;
            }
        });
    }
    getRefreshSessionMw() {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            const accessToken = this.getAccessToken(req);
            if (!accessToken) {
                res.status(401);
                return next();
            }
            try {
                const oidcClient = yield this.oidcClientGetter(req);
                const tokens = yield this.refreshSession(oidcClient, accessToken);
                if (tokens) {
                    if (tokens.access_token) {
                        const details = yield this.getSessionDetails(oidcClient, tokens.access_token, true);
                        setSessionCookies(res, details);
                        res.status(200);
                    }
                    else {
                        this.clearSessionCache(accessToken);
                        clearSessionCookies(req, res);
                        logger_1.default.error("Failed refreshing the session because no access token has been returned", {
                            tokens
                        });
                        res.status(500);
                    }
                }
                else {
                    this.clearSessionCache(accessToken);
                    clearSessionCookies(req, res);
                    res.status(403);
                }
            }
            catch (error) {
                logger_1.default.error("Failed refreshing the session", {
                    message: error.message,
                    fullError: error
                });
                this.clearSessionCache(accessToken);
                clearSessionCookies(req, res);
                res.status(500);
            }
            next();
        });
    }
    getSessionMw(options) {
        return (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            const opts = Object.assign(Object.assign({}, defaultSessionMwOps), options);
            const token = this.getAccessToken(req);
            const oidcClient = yield this.oidcClientGetter(req);
            if (opts.failOnMissing && !token) {
                return next(new InvalidSession("Invalid session"));
            }
            try {
                if (token) {
                    res.locals.session = {
                        accessToken: token
                    };
                    if (opts.loadUserInfo) {
                        res.locals.session.userInfo = yield oidcClient.userinfo(token);
                    }
                    if (opts.loadIntrospect) {
                        const details = yield this.getSessionDetails(oidcClient, token, true);
                        res.locals.session.introspect = details.idTokenDecoded;
                    }
                }
                next();
            }
            catch (error) {
                if (opts.failOnMissing) {
                    next(error);
                }
                else {
                    res.locals.session = undefined;
                    next();
                }
            }
        });
    }
    getEmailFromCookie(req) {
        if (req.cookies[UserEmailCookieName]) {
            return req.cookies[UserEmailCookieName];
        }
        else {
            return undefined;
        }
    }
    /* eslint-disable @typescript-eslint/camelcase */
    getRegistrationUrl(oidcClient, redirectUri) {
        return __awaiter(this, void 0, void 0, function* () {
            return oidcClient
                .authorizationUrl({
                redirect_uri: redirectUri
            })
                .replace("/auth?", "/registrations?");
        });
    }
}
exports.SessionMgmt = SessionMgmt;
//# sourceMappingURL=session-middlewares.js.map