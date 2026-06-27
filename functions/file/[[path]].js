import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { fetchSecurityConfig } from "../utils/sysConfig";
import { TelegramAPI } from "../utils/storage/telegramAPI";
import { DiscordAPI } from "../utils/storage/discordAPI";
import { HuggingFaceAPI } from "../utils/storage/huggingfaceAPI";
import { WebDAVAPI } from "../utils/storage/webdavAPI";
import { resolveWebDAVConfig } from "../utils/webdavConfig";
import {
    setCommonHeaders, setRangeHeaders, handleHeadRequest, getFileContent, isTgChannel,
    returnWithCheck, return404, returnBlockImg, isDomainAllowed, FILE_CACHE_CONTROL
} from './fileTools';
import { getDatabase } from '../utils/databaseAdapter.js';
import { authenticate, AUTH_SCOPE } from '../utils/auth/authCore.js';

// ====================================================
// 辅助函数：使用 Web Crypto API 验证 HMAC-SHA256 签名
// 移至 onRequest 上方，并增加环境兼容性处理
// ====================================================
async function verifyHmacSha256(message, receivedHex, secret) {
    // 兼容部分未将 crypto 挂载到全局的构建/测试环境
    const cryptoProvider = typeof crypto !== 'undefined' ? crypto : (typeof globalThis !== 'undefined' ? globalThis.crypto : null);
    if (!cryptoProvider || !cryptoProvider.subtle) {
        throw new Error("Web Crypto API is not supported in this environment");
    }

    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const messageData = encoder.encode(message);

    const cryptoKey = await cryptoProvider.subtle.importKey(
        "raw",
        keyData,
        { name: "HMAC", hash: { name: "SHA-256" } }, // 使用标准的 hash 对象结构
        false,
        ["sign"]
    );

    const signature = await cryptoProvider.subtle.sign(
        "HMAC",
        cryptoKey,
        messageData
    );

    const expectedHex = Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    return expectedHex === receivedHex;
}

export async function onRequest(context) {  
    const {
        request, 
        env, 
        params, 
        waitUntil, 
        next, 
        data, 
    } = context;

    const url = new URL(request.url);

    // ====================================================
    // 1. 安全校验：非管理员预览请求，必须校验短期数字签名
    // ====================================================
    const fromAdmin = url.searchParams.get('from') === 'admin';
    if (!fromAdmin) {
        const secretKey = env.SECURE_TOKEN_SECRET;
        
        if (secretKey) {
            const token = url.searchParams.get('token');
            const expires = url.searchParams.get('expires');

            if (!token || !expires) {
                return new Response('Error: Access Denied (Missing Signature Token)', { status: 403 });
            }

            const now = Math.floor(Date.now() / 1000);
            if (now > parseInt(expires, 10)) {
                return new Response('Error: Link Expired', { status: 403 });
            }

            const filePath = decodeURIComponent(url.pathname); 
            const message = `${filePath}|${expires}`;
            try {
                const isValid = await verifyHmacSha256(message, token, secretKey);
                if (!isValid) {
                    return new Response('Error: Invalid Signature Token', { status: 403 });
                }
            } catch (err) {
                return new Response(`Error: Signature Verification Failed (${err.message})`, { status: 500 });
            }
        }
    }
    // ====================================================

    // 解码文件ID
    let fileId = '';
    try {
        params.path = decodeURIComponent(params.path);
        fileId = params.path.split(',').join('/');
    } catch (e) {
        return new Response('Error: Decode Image ID Failed', { status: 400 });
    }

    // 读取安全配置，解析必要参数
    const securityConfig = await fetchSecurityConfig(env);
    context.securityConfig = securityConfig;

    context.url = url;

    const Referer = request.headers.get('Referer')
    context.Referer = Referer;

    context.fileAccess = await buildFileAccessContext(context);

    // 检查引用域名是否被允许
    if (!isDomainAllowed(context)) {
        return await returnBlockImg(url);
    }

    // 从数据库中获取图片记录
    const db = getDatabase(env);
    const imgRecord = await db.getWithMetadata(fileId);
    if (!imgRecord) {
        return new Response('Error: Image Not Found', { status: 404 });
    }

    // 如果metadata不存在，只可能是之前未设置KV，且存储在Telegraph上的图片
    if (!imgRecord.metadata) {
        imgRecord.metadata = {};
    }

    const fileName = imgRecord.metadata?.FileName || fileId;
    const encodedFileName = encodeURIComponent(fileName);
    const fileType = imgRecord.metadata?.FileType || null;

    // 检查文件可访问状态
    let accessRes = await returnWithCheck(context, imgRecord);
    if (accessRes.status !== 200) {
        return accessRes; // 如果不可访问，直接返回
    }

    /* Cloudflare R2渠道 */
    if (imgRecord.metadata?.Channel === 'CloudflareR2') {
        return await handleR2File(context, fileId, encodedFileName, fileType);
    }

    /* S3渠道 */
    if (imgRecord.metadata?.Channel === "S3") {
        return await handleS3File(context, imgRecord.metadata, encodedFileName, fileType);
    }

    /* Discord 渠道 */
    if (imgRecord.metadata?.Channel === 'Discord') {
        if (imgRecord.metadata?.IsChunked === true) {
            return await handleDiscordChunkedFile(context, imgRecord, encodedFileName, fileType);
        }
        return await handleDiscordFile(context, imgRecord.metadata, encodedFileName, fileType);
    }

    /* HuggingFace 渠道 */
    if (imgRecord.metadata?.Channel === 'HuggingFace') {
        return await handleHuggingFaceFile(context, imgRecord.metadata, encodedFileName, fileType);
    }

    /* WebDAV 渠道 */
    if (imgRecord.metadata?.Channel === 'WebDAV') {
        return await handleWebDAVFile(context, imgRecord.metadata, encodedFileName, fileType);
    }

    /* 外链渠道 */
    if (imgRecord.metadata?.Channel === 'External') {
        return Response.redirect(imgRecord.metadata?.ExternalLink, 302);
    }

    /* Telegram及Telegraph渠道 */
    let targetUrl = '';

    if (isTgChannel(imgRecord)) {
        let TgFileID = ''; 

        if (imgRecord.metadata?.Channel === 'Telegram') {
            TgFileID = fileId.split('.')[0]; 
        } else if (imgRecord.metadata?.Channel === 'TelegramNew') {
            if (imgRecord.metadata?.IsChunked === true) {
                return await handleTelegramChunkedFile(context, imgRecord, encodedFileName, fileType);
            }

            TgFileID = imgRecord.metadata?.TgFileId;

            if (TgFileID === null) {
                return new Response('Error: Failed to fetch image', { status: 500 });
            }
        }

        const TgBotToken = imgRecord.metadata?.TgBotToken || env.TG_BOT_TOKEN;
        const TgProxyUrl = imgRecord.metadata?.TgProxyUrl || '';
        const tgApi = new TelegramAPI(TgBotToken, TgProxyUrl);
        const filePath = await tgApi.getFilePath(TgFileID);
        if (filePath === null) {
            return new Response('Error: Failed to fetch image path', { status: 500 });
        }
        const fileDomain = TgProxyUrl ? `https://${TgProxyUrl}` : 'https://api.telegram.org';
        targetUrl = `${fileDomain}/file/bot${TgBotToken}/${filePath}`;
    } else {
        targetUrl = 'https://telegra.ph/' + url.pathname + url.search;
    }

    try {
        const response = await getFileContent(request, targetUrl);

        if (response === null) {
            return new Response('Error: Failed to fetch image', { status: 500 });
        } else if (response.status === 404) {
            return await return404(url);
        }

        const headers = new Headers(response.headers);
        setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));

        const newRes = new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers,
        });

        return newRes;
    } catch (error) {
        return new Response('Error: ' + error, { status: 500 });
    }
}

async function buildFileAccessContext(context) {
    const { request, env, url } = context;
    const fromAdmin = url.searchParams.get('from') === 'admin';
    const fileAccess = {
        isAdminPreview: fromAdmin,
        adminAuthResult: { authorized: false, authType: null },
        cacheControl: undefined,
    };

    if (fileAccess.isAdminPreview) {
        fileAccess.adminAuthResult = await authenticate({
            env,
            request,
            requiredPermission: 'manage',
            authScope: AUTH_SCOPE.ADMIN,
        });
    }

    return fileAccess;
}

function getFileCacheControl(context) {
    return context.fileAccess?.cacheControl;
}

function getChunkedFileCacheControl(context) {
    return getFileCacheControl(context) === FILE_CACHE_CONTROL.NO_STORE
        ? FILE_CACHE_CONTROL.NO_STORE
        : FILE_CACHE_CONTROL.PRIVATE;
}

// 处理 Telegram 渠道分片文件读取
async function handleTelegramChunkedFile(context, imgRecord, encodedFileName, fileType) {
    const { env, request, url, Referer } = context;

    const metadata = imgRecord.metadata;
    const TgBotToken = metadata.TgBotToken || env.TG_BOT_TOKEN;
    const TgProxyUrl = metadata.TgProxyUrl || '';

    let chunks = [];
    try {
        if (imgRecord.value) {
            chunks = JSON.parse(imgRecord.value);
            chunks.sort((a, b) => a.index - b.index);
        }
    } catch (parseError) {
        console.error('Failed to parse chunks data:', parseError);
        return new Response('Error: Invalid chunks data', { status: 500 });
    }

    if (chunks.length === 0) {
        return new Response('Error: No chunks found for this file', { status: 500 });
    }

    const expectedChunks = metadata.TotalChunks || chunks.length;
    if (chunks.length !== expectedChunks) {
        return new Response(`Error: Missing chunks, expected ${expectedChunks}, got ${chunks.length}`, { status: 500 });
    }

    const totalSize = chunks.reduce((total, chunk) => total + (chunk.size || 0), 0);

    const headers = new Headers();
    setCommonHeaders(headers, encodedFileName, fileType, getChunkedFileCacheControl(context));
    headers.set('Content-Length', totalSize.toString());

    const etag = `"${metadata.TimeStamp || Date.now()}-${totalSize}"`;
    headers.set('ETag', etag);

    const ifNoneMatch = request.headers.get('If-None-Match');
    if (ifNoneMatch && ifNoneMatch === etag) {
        return new Response(null, {
            status: 304,
            headers: {
                'ETag': etag,
                'Cache-Control': headers.get('Cache-Control'),
                'Accept-Ranges': 'bytes'
            }
        });
    }

    const range = request.headers.get('Range');
    let rangeStart = 0;
    let rangeEnd = totalSize - 1;
    let isRangeRequest = false;

    if (range) {
        const matches = range.match(/bytes=(\d+)-(\d*)/);
        if (matches) {
            rangeStart = parseInt(matches[1]);
            rangeEnd = matches[2] ? parseInt(matches[2]) : totalSize - 1;
            isRangeRequest = true;

            if (rangeStart >= totalSize || rangeEnd >= totalSize || rangeStart > rangeEnd) {
                return new Response('Range Not Satisfiable', { status: 416 });
            }
        }
    }

    if (request.method === 'HEAD') {
        return handleHeadRequest(headers, etag);
    }

    try {
        const stream = new ReadableStream({
            async start(controller) {
                try {
                    let currentPosition = 0;

                    for (let i = 0; i < chunks.length; i++) {
                        const chunk = chunks[i];
                        const chunkSize = chunk.size || 0;

                        if (currentPosition + chunkSize <= rangeStart) {
                            currentPosition += chunkSize;
                            continue;
                        }

                        if (currentPosition > rangeEnd) {
                            break;
                        }

                        const chunkData = await fetchTelegramChunkWithRetry(TgBotToken, chunk, TgProxyUrl, 3);
                        if (!chunkData) {
                            throw new Error(`Failed to fetch chunk ${chunk.index} after retries`);
                        }

                        const chunkStart = Math.max(0, rangeStart - currentPosition);
                        const chunkEnd = Math.min(chunkSize, rangeEnd - currentPosition + 1);

                        if (chunkStart > 0 || chunkEnd < chunkSize) {
                            const partialData = chunkData.slice(chunkStart, chunkEnd);
                            controller.enqueue(partialData);
                        } else {
                            controller.enqueue(chunkData);
                        }

                        currentPosition += chunkSize;
                    }

                    controller.close();
                } catch (error) {
                    controller.error(error);
                }
            }
        });

        if (isRangeRequest) {
            setRangeHeaders(headers, rangeStart, rangeEnd, totalSize);

            return new Response(stream, {
                status: 206, 
                headers,
            });
        } else {
            headers.set('Cache-Control', getChunkedFileCacheControl(context)); 

            return new Response(stream, {
                status: 200,
                headers,
            });
        }

    } catch (error) {
        return new Response(`Error: Failed to reconstruct chunked file - ${error.message}`, { status: 500 });
    }
}

async function fetchTelegramChunkWithRetry(botToken, chunk, proxyUrl = '', maxRetries = 3) {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const tgApi = new TelegramAPI(botToken, proxyUrl);
            const response = await tgApi.getFileContent(chunk.fileId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const chunkData = await response.arrayBuffer();
            const actualSize = chunkData.byteLength;

            if (chunk.size && actualSize !== chunk.size) {
                console.warn(`Chunk ${chunk.index} size mismatch: expected ${chunk.size}, got ${actualSize}`);
            }

            return new Uint8Array(chunkData);

        } catch (error) {
            console.warn(`Chunk ${chunk.index} fetch attempt ${attempt + 1} failed:`, error.message);

            if (attempt === maxRetries - 1) {
                return null; 
            }
            await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
        }
    }
    return null;
}

// 处理 Discord 渠道分片文件读取
async function handleDiscordChunkedFile(context, imgRecord, encodedFileName, fileType) {
    const { request, url, Referer } = context;

    const metadata = imgRecord.metadata;
    const botToken = metadata.DiscordBotToken;
    const proxyUrl = metadata.DiscordProxyUrl;

    let chunks = [];
    try {
        if (imgRecord.value) {
            chunks = JSON.parse(imgRecord.value);
            chunks.sort((a, b) => a.index - b.index);
        }
    } catch (parseError) {
        console.error('Failed to parse Discord chunks data:', parseError);
        return new Response('Error: Invalid chunks data', { status: 500 });
    }

    if (chunks.length === 0) {
        return new Response('Error: No chunks found for this file', { status: 500 });
    }

    const expectedChunks = metadata.TotalChunks || chunks.length;
    if (chunks.length !== expectedChunks) {
        return new Response(`Error: Missing chunks, expected ${expectedChunks}, got ${chunks.length}`, { status: 500 });
    }

    const totalSize = chunks.reduce((total, chunk) => total + (chunk.size || 0), 0);

    const headers = new Headers();
    setCommonHeaders(headers, encodedFileName, fileType, getChunkedFileCacheControl(context));
    headers.set('Content-Length', totalSize.toString());

    const etag = `"${metadata.TimeStamp || Date.now()}-${totalSize}"`;
    headers.set('ETag', etag);

    const ifNoneMatch = request.headers.get('If-None-Match');
    if (ifNoneMatch && ifNoneMatch === etag) {
        return new Response(null, {
            status: 304,
            headers: {
                'ETag': etag,
                'Cache-Control': headers.get('Cache-Control'),
                'Accept-Ranges': 'bytes'
            }
        });
    }

    const range = request.headers.get('Range');
    let rangeStart = 0;
    let rangeEnd = totalSize - 1;
    let isRangeRequest = false;

    if (range) {
        const matches = range.match(/bytes=(\d+)-(\d*)/);
        if (matches) {
            rangeStart = parseInt(matches[1]);
            rangeEnd = matches[2] ? parseInt(matches[2]) : totalSize - 1;
            isRangeRequest = true;

            if (rangeStart >= totalSize || rangeEnd >= totalSize || rangeStart > rangeEnd) {
                return new Response('Range Not Satisfiable', { status: 416 });
            }
        }
    }

    if (request.method === 'HEAD') {
        return handleHeadRequest(headers, etag);
    }

    try {
        const stream = new ReadableStream({
            async start(controller) {
                try {
                    let currentPosition = 0;

                    for (let i = 0; i < chunks.length; i++) {
                        const chunk = chunks[i];
                        const chunkSize = chunk.size || 0;

                        if (currentPosition + chunkSize <= rangeStart) {
                            currentPosition += chunkSize;
                            continue;
                        }

                        if (currentPosition > rangeEnd) {
                            break;
                        }

                        const chunkData = await fetchDiscordChunkWithRetry(botToken, metadata.DiscordChannelId, chunk, proxyUrl, 3);
                        if (!chunkData) {
                            throw new Error(`Failed to fetch Discord chunk ${chunk.index} after retries`);
                        }

                        const chunkStart = Math.max(0, rangeStart - currentPosition);
                        const chunkEnd = Math.min(chunkSize, rangeEnd - currentPosition + 1);

                        if (chunkStart > 0 || chunkEnd < chunkSize) {
                            const partialData = chunkData.slice(chunkStart, chunkEnd);
                            controller.enqueue(partialData);
                        } else {
                            controller.enqueue(chunkData);
                        }

                        currentPosition += chunkSize;
                    }

                    controller.close();
                } catch (error) {
                    controller.error(error);
                }
            }
        });

        if (isRangeRequest) {
            setRangeHeaders(headers, rangeStart, rangeEnd, totalSize);

            return new Response(stream, {
                status: 206, 
                headers,
            });
        } else {
            headers.set('Cache-Control', getChunkedFileCacheControl(context));

            return new Response(stream, {
                status: 200,
                headers,
            });
        }

    } catch (error) {
        return new Response(`Error: Failed to reconstruct Discord chunked file - ${error.message}`, { status: 500 });
    }
}

async function fetchDiscordChunkWithRetry(botToken, channelId, chunk, proxyUrl, maxRetries = 3) {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const discordAPI = new DiscordAPI(botToken);
            let fileUrl = await discordAPI.getFileURL(channelId, chunk.messageId);

            if (!fileUrl) {
                throw new Error('Failed to get attachment URL from Discord API');
            }

            if (proxyUrl) {
                fileUrl = fileUrl.replace('https://cdn.discordapp.com', `https://${proxyUrl}`);
            }

            const response = await fetch(fileUrl);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const chunkData = await response.arrayBuffer();
            const actualSize = chunkData.byteLength;

            if (chunk.size && actualSize !== chunk.size) {
                console.warn(`Discord chunk ${chunk.index} size mismatch: expected ${chunk.size}, got ${actualSize}`);
            }

            return new Uint8Array(chunkData);

        } catch (error) {
            console.warn(`Discord chunk ${chunk.index} fetch attempt ${attempt + 1} failed:`, error.message);

            if (attempt === maxRetries - 1) {
                return null; 
            }
            await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
        }
    }
    return null;
}

// 处理R2文件读取
async function handleR2File(context, fileId, encodedFileName, fileType) {
    const { env, request, url, Referer } = context;

    try {
        if (typeof env.img_r2 == "undefined" || env.img_r2 == null || env.img_r2 == "") {
            return new Response('Error: Please configure R2 database', { status: 500 });
        }

        const R2DataBase = env.img_r2;
        const range = request.headers.get('Range');
        let object;

        if (range) {
            const matches = range.match(/bytes=(\d+)-(\d*)/);
            if (matches) {
                const start = parseInt(matches[1]);
                const end = matches[2] ? parseInt(matches[2]) : undefined;

                const rangeOptions = {
                    range: {
                        offset: start
                    }
                };
                if (end !== undefined) {
                    rangeOptions.range.length = end - start + 1;
                }

                object = await R2DataBase.get(fileId, rangeOptions);
            } else {
                object = await R2DataBase.get(fileId);
            }
        } else {
            object = await R2DataBase.get(fileId);
        }

        if (object === null) {
            return new Response('Error: Failed to fetch file', { status: 500 });
        }

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));

        if (request.method === 'HEAD') {
            return handleHeadRequest(headers);
        }

        if (range && object.range) {
            headers.set('Content-Range', `bytes ${object.range.offset}-${object.range.offset + object.range.length - 1}/${object.size}`);
            headers.set('Content-Length', object.range.length.toString());

            return new Response(object.body, {
                status: 206, 
                headers,
            });
        }

        return new Response(object.body, {
            status: 200,
            headers,
        });
    } catch (error) {
        return new Response(`Error: Failed to fetch from R2 - ${error.message}`, { status: 500 });
    }
}

// 处理S3文件读取
async function handleS3File(context, metadata, encodedFileName, fileType) {
    const { Referer, url, request } = context;
    const cdnFileUrl = metadata?.S3CdnFileUrl;

    if (cdnFileUrl) {
        try {
            if (request.method === 'HEAD') {
                const headers = new Headers();
                setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));
                return handleHeadRequest(headers);
            }

            const fetchHeaders = {};
            const range = request.headers.get('Range');
            if (range) {
                fetchHeaders['Range'] = range;
            }

            const response = await fetch(cdnFileUrl, {
                method: 'GET',
                headers: fetchHeaders
            });

            if (!response.ok && response.status !== 206) {
                console.warn(`CDN fetch failed (${response.status}), falling back to S3 API`);
                return await handleS3FileViaAPI(context, metadata, encodedFileName, fileType);
            }

            const headers = new Headers();
            setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));

            if (response.headers.get('Content-Length')) {
                headers.set('Content-Length', response.headers.get('Content-Length'));
            }
            if (response.headers.get('Content-Range')) {
                headers.set('Content-Range', response.headers.get('Content-Range'));
            }

            return new Response(response.body, {
                status: response.status,
                headers
            });

        } catch (error) {
            console.error(`CDN fetch error: ${error.message}, falling back to S3 API`);
            return await handleS3FileViaAPI(context, metadata, encodedFileName, fileType);
        }
    }

    return await handleS3FileViaAPI(context, metadata, encodedFileName, fileType);
}

// 通过 S3 API 读取文件
async function handleS3FileViaAPI(context, metadata, encodedFileName, fileType) {
    const { Referer, url, request } = context;

    const s3Client = new S3Client({
        region: metadata?.S3Region || "auto",
        endpoint: metadata?.S3Endpoint,
        credentials: {
            accessKeyId: metadata?.S3AccessKeyId,
            secretAccessKey: metadata?.S3SecretAccessKey
        },
        forcePathStyle: metadata?.S3PathStyle || false
    });

    const bucketName = metadata?.S3BucketName;
    const key = metadata?.S3FileKey;

    try {
        const range = request.headers.get('Range');
        const commandParams = {
            Bucket: bucketName,
            Key: key
        };

        if (range) {
            commandParams.Range = range;
        }

        const command = new GetObjectCommand(commandParams);
        const response = await s3Client.send(command);

        const headers = new Headers();
        setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));

        if (response.ContentLength) {
            headers.set('Content-Length', response.ContentLength.toString());
        }

        if (response.ContentRange) {
            headers.set('Content-Range', response.ContentRange);
        }

        if (request.method === 'HEAD') {
            return handleHeadRequest(headers);
        }

        const statusCode = range ? 206 : 200; 
        return new Response(response.Body, {
            status: statusCode,
            headers
        });

    } catch (error) {
        return new Response(`Error: Failed to fetch from S3 - ${error.message}`, { status: 500 });
    }
}

// 处理 Discord 文件读取
async function handleDiscordFile(context, metadata, encodedFileName, fileType) {
    const { env, request, url, Referer } = context;

    try {
        let fileUrl = null;
        if (metadata.DiscordMessageId && metadata.DiscordChannelId && metadata.DiscordBotToken) {
            const discordAPI = new DiscordAPI(metadata.DiscordBotToken);
            fileUrl = await discordAPI.getFileURL(metadata.DiscordChannelId, metadata.DiscordMessageId);
        }

        if (!fileUrl) {
            return new Response('Error: Discord file URL not found', { status: 500 });
        }

        if (metadata.DiscordProxyUrl) {
            fileUrl = fileUrl.replace('https://cdn.discordapp.com', `https://${metadata.DiscordProxyUrl}`);
        }

        if (request.method === 'HEAD') {
            const headers = new Headers();
            setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));
            return handleHeadRequest(headers);
        }

        const fetchHeaders = {};
        const range = request.headers.get('Range');
        if (range) {
            fetchHeaders['Range'] = range;
        }

        const response = await fetch(fileUrl, {
            method: 'GET',
            headers: fetchHeaders
        });

        if (!response.ok && response.status !== 206) {
            return new Response(`Error: Failed to fetch from Discord - ${response.status}`, { status: response.status });
        }

        const headers = new Headers();
        setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));

        if (response.headers.get('Content-Length')) {
            headers.set('Content-Length', response.headers.get('Content-Length'));
        }
        if (response.headers.get('Content-Range')) {
            headers.set('Content-Range', response.headers.get('Content-Range'));
        }

        return new Response(response.body, {
            status: response.status,
            headers
        });

    } catch (error) {
        return new Response(`Error: Failed to fetch from Discord - ${error.message}`, { status: 500 });
    }
}

// 处理 HuggingFace 文件读取
async function handleHuggingFaceFile(context, metadata, encodedFileName, fileType) {
    const { request, url, Referer } = context;

    try {
        const hfRepo = metadata.HfRepo;
        const hfFilePath = metadata.HfFilePath;
        const hfToken = metadata.HfToken;
        const hfIsPrivate = metadata.HfIsPrivate || false;

        if (!hfRepo || !hfFilePath) {
            return new Response('Error: HuggingFace file info not found', { status: 500 });
        }

        const fileUrl = metadata.HfFileUrl || `https://huggingface.co/datasets/${hfRepo}/resolve/main/${hfFilePath}`;

        if (request.method === 'HEAD') {
            const headers = new Headers();
            setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));
            return handleHeadRequest(headers);
        }

        const fetchHeaders = {};

        if (hfIsPrivate && hfToken) {
            fetchHeaders['Authorization'] = `Bearer ${hfToken}`;
        }

        const range = request.headers.get('Range');
        if (range) {
            fetchHeaders['Range'] = range;
        }

        const response = await fetch(fileUrl, {
            method: 'GET',
            headers: fetchHeaders
        });

        if (!response.ok && response.status !== 206) {
            return new Response(`Error: Failed to fetch from HuggingFace - ${response.status}`, { status: response.status });
        }

        const headers = new Headers();
        setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));

        if (response.headers.get('Content-Length')) {
            headers.set('Content-Length', response.headers.get('Content-Length'));
        }
        if (response.headers.get('Content-Range')) {
            headers.set('Content-Range', response.headers.get('Content-Range'));
        }

        return new Response(response.body, {
            status: response.status,
            headers
        });

    } catch (error) {
        return new Response(`Error: Failed to fetch from HuggingFace - ${error.message}`, { status: 500 });
    }
}

// 处理 WebDAV 文件读取
async function handleWebDAVFile(context, metadata, encodedFileName, fileType) {
    const { request, url, Referer } = context;

    try {
        const filePath = metadata.WebDAVFilePath;
        const publicUrl = metadata.WebDAVPublicUrl;

        if (!filePath && !publicUrl) {
            return new Response('Error: WebDAV file info not found', { status: 500 });
        }

        const headers = new Headers();
        setCommonHeaders(headers, encodedFileName, fileType, getFileCacheControl(context));

        const fetchHeaders = {};
        const range = request.headers.get('Range');
        if (range) {
            fetchHeaders['Range'] = range;
        }

        let response;
        if (publicUrl) {
            response = await fetch(publicUrl, {
                method: request.method === 'HEAD' ? 'HEAD' : 'GET',
                headers: fetchHeaders,
            });
        } else {
            const webdavConfig = await resolveWebDAVConfig(context.env, metadata);
            if (!webdavConfig) {
                return new Response('Error: WebDAV channel config not found', { status: 500 });
            }

            const webdavAPI = new WebDAVAPI(webdavConfig);
            response = await webdavAPI.getFile(filePath, {
                method: request.method === 'HEAD' ? 'HEAD' : 'GET',
                headers: fetchHeaders,
            });
        }

        if (!response.ok && response.status !== 206 && response.status !== 304) {
            return new Response(`Error: Failed to fetch from WebDAV - ${response.status}`, { status: response.status });
        }

        if (response.headers.get('Content-Length')) {
            headers.set('Content-Length', response.headers.get('Content-Length'));
        }
        if (response.headers.get('Content-Range')) {
            headers.set('Content-Range', response.headers.get('Content-Range'));
        }
        if (response.headers.get('ETag')) {
            headers.set('ETag', response.headers.get('ETag'));
        }
        if (response.status === 304) {
            return new Response(null, { status: 304, headers });
        }
        if (request.method === 'HEAD') {
            return handleHeadRequest(headers, response.headers.get('ETag'));
        }

        return new Response(response.body, {
            status: response.status,
            headers
        });

    } catch (error) {
        return new Response(`Error: Failed to fetch from WebDAV - ${error.message}`, { status: 500 });
    }
}
