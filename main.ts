import { Context, Hono } from "https://deno.land/x/hono@v4.3.11/mod.ts";
import { crypto } from "https://deno.land/std@0.224.0/crypto/mod.ts";

type StatusCode =
    | 100
    | 101
    | 102
    | 103
    | 200
    | 201
    | 202
    | 203
    | 204
    | 205
    | 206
    | 207
    | 300
    | 301
    | 302
    | 303
    | 304
    | 305
    | 307
    | 308
    | 400
    | 401
    | 402
    | 403
    | 404
    | 405
    | 406
    | 407
    | 408
    | 409
    | 410
    | 411
    | 412
    | 413
    | 414
    | 415
    | 416
    | 417
    | 418
    | 422
    | 425
    | 426
    | 428
    | 429
    | 431
    | 451
    | 500
    | 501
    | 502
    | 503
    | 504
    | 505
    | 506
    | 507
    | 508
    | 510
    | 511;

// ================== 常量配置 ===================
const CONFIG = {
    NIST_BASE_URL: "https://beacon.nist.gov/beacon/2.0/pulse/time/next",
    NIST_LAST_URL: "https://beacon.nist.gov/beacon/2.0/pulse/last",
    DRAND_BASE_URL: "https://api.drand.sh/public",
    DEFAULT_MIN: 0,
    DEFAULT_MAX: 100,
    DEFAULT_NUM: 1,
    GENESIS_TIME: 1595431050,
    PERIOD: 30,
    REQUEST_TIMEOUT_MS: 5000, // 请求超时时间（毫秒）
};

const ERROR_CODE = {
    NIST_PULSE_NOT_AVAILABLE: "NIST_PULSE_NOT_AVAILABLE",
    DRAND_TOO_EARLY: "DRAND_TOO_EARLY",
    INVALID_PARAMETERS: "INVALID_PARAMETERS",
    INTERNAL_ERROR: "INTERNAL_ERROR",
    MISSING_PARAMETER: "MISSING_PARAMETER",
    NIST_API_TIMEOUT: "NIST_API_TIMEOUT",
    DRAND_API_TIMEOUT: "DRAND_API_TIMEOUT",
    INVALID_NIST_RESPONSE: "INVALID_NIST_RESPONSE",
} as const;

interface NistResponse {
    pulse?: {
        outputValue: string;
        timeStamp?: string;
        [key: string]: unknown;
    };
}

interface DrandResponse {
    round: number;
    randomness: string;
    signature: string;
    previous_signature: string;
}

interface RandomResponse {
    timestamp: string;
    numbers: number[];
    nistValue: string;
    drandValue: string;
    combinedValue: string;
}

interface ErrorResponse {
    error: string;
    errorCode: string;
    timestamp?: string;
    suggestion?: string;
    genesisTime?: number;
    validRanges?: {
        num: string;
        min: string;
        max: string;
    };
}

class MT19937 {
    private readonly N = 624;
    private readonly M = 397;
    private readonly MATRIX_A = 0x9908b0df;
    private readonly UPPER_MASK = 0x80000000;
    private readonly LOWER_MASK = 0x7fffffff;

    private mt: number[];
    private mti: number;

    constructor() {
        this.mt = new Array(this.N);
        this.mti = this.N + 1;
    }

    async initWithSeed(seed: string) {
        const hashBuffer = await crypto.subtle.digest(
            "SHA-512",
            new TextEncoder().encode(seed),
        );
        this.init_by_array(Array.from(new Uint32Array(hashBuffer)));
    }

    private init_by_array(initKey: number[]) {
        this.init_genrand(19650218);
        let i = 1;
        let j = 0;
        for (let k = Math.max(this.N, initKey.length); k; k--) {
            this.mt[i] = (this.mt[i] ^
                ((this.mt[i - 1] ^ (this.mt[i - 1] >>> 30)) * 1664525)) +
                initKey[j] +
                j;
            this.mt[i] >>>= 0;
            i++;
            j++;
            if (i >= this.N) {
                this.mt[0] = this.mt[this.N - 1];
                i = 1;
            }
            if (j >= initKey.length) j = 0;
        }
        for (let k = this.N - 1; k; k--) {
            this.mt[i] = (this.mt[i] ^
                ((this.mt[i - 1] ^ (this.mt[i - 1] >>> 30)) * 1566083941)) -
                i;
            this.mt[i] >>>= 0;
            i++;
            if (i >= this.N) {
                this.mt[0] = this.mt[this.N - 1];
                i = 1;
            }
        }
        this.mt[0] = 0x80000000;
    }

    private init_genrand(s: number) {
        this.mt[0] = s >>> 0;
        for (this.mti = 1; this.mti < this.N; this.mti++) {
            this.mt[this.mti] = 1812433253 *
                    (this.mt[this.mti - 1] ^ (this.mt[this.mti - 1] >>> 30)) +
                this.mti;
            this.mt[this.mti] >>>= 0;
        }
    }

    next(): number {
        let y: number;
        const mag01 = [0x0, this.MATRIX_A];

        if (this.mti >= this.N) {
            let kk: number;

            for (kk = 0; kk < this.N - this.M; kk++) {
                y = (this.mt[kk] & this.UPPER_MASK) |
                    (this.mt[kk + 1] & this.LOWER_MASK);
                this.mt[kk] = this.mt[kk + this.M] ^ (y >>> 1) ^ mag01[y & 0x1];
            }
            for (; kk < this.N - 1; kk++) {
                y = (this.mt[kk] & this.UPPER_MASK) |
                    (this.mt[kk + 1] & this.LOWER_MASK);
                this.mt[kk] = this.mt[kk + (this.M - this.N)] ^ (y >>> 1) ^
                    mag01[y & 0x1];
            }
            y = (this.mt[this.N - 1] & this.UPPER_MASK) |
                (this.mt[0] & this.LOWER_MASK);
            this.mt[this.N - 1] = this.mt[this.M - 1] ^ (y >>> 1) ^
                mag01[y & 0x1];

            this.mti = 0;
        }

        y = this.mt[this.mti++];

        y ^= y >>> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >>> 18;

        return y >>> 0;
    }

    generateNumbers(count: number, min: number, max: number): number[] {
        const range = max - min;
        return Array.from({ length: count }, () => {
            const fraction = this.next() / 0x100000000;
            return Math.floor(fraction * range + min);
        });
    }
}

function normalizeTimestamp(ts: string): string {
    const numericTs = ts.replace(/\D/g, "");
    return numericTs.length <= 10
        ? (parseInt(numericTs, 10) * 1000).toString()
        : numericTs;
}

function normalizeToNearestPeriod(timestamp: string): string {
    const tsInMillis = parseInt(normalizeTimestamp(timestamp));
    const tsInSeconds = Math.floor(tsInMillis / 1000);
    const mod = tsInSeconds % CONFIG.PERIOD;
    const normalizedSeconds = tsInSeconds - mod;
    return (normalizedSeconds * 1000).toString();
}

function isNumericValid(min: number, max: number, num: number): boolean {
    return !isNaN(min) &&
        !isNaN(max) &&
        !isNaN(num) &&
        min < max &&
        num > 0 &&
        num <= 1000;
}

function getNistUrl(timestamp: string | "last"): string {
    return timestamp === "last"
        ? CONFIG.NIST_LAST_URL
        : `${CONFIG.NIST_BASE_URL}/${normalizeTimestamp(timestamp)}`;
}

function getDrandUrl(timestamp: string | "last"): string {
    if (timestamp === "last") {
        return `${CONFIG.DRAND_BASE_URL}/latest`;
    }
    const ts = parseInt(normalizeTimestamp(timestamp)) / 1000;
    const round = Math.floor((ts - CONFIG.GENESIS_TIME) / CONFIG.PERIOD);
    return `${CONFIG.DRAND_BASE_URL}/${round}`;
}

async function fetchNistData(timestamp: string): Promise<NistResponse> {
    const url = getNistUrl(timestamp);
    const controller = new AbortController();
    const timeoutId = setTimeout(
        () => controller.abort(),
        CONFIG.REQUEST_TIMEOUT_MS,
    );

    try {
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (response.status === 404) {
            throw new Error("Pulse Not Available.");
        }
        if (!response.ok) {
            throw new Error(`NIST returned status: ${response.status}`);
        }
        const data: NistResponse = await response.json();
        if (!data.pulse?.outputValue) {
            throw new Error("Invalid NIST response");
        }
        return data;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error instanceof Error && error.name === "AbortError") {
            throw new Error("NIST API Timeout");
        }
        throw error;
    }
}

async function fetchDrandData(timestamp: string): Promise<DrandResponse> {
    const url = getDrandUrl(timestamp);
    const controller = new AbortController();
    const timeoutId = setTimeout(
        () => controller.abort(),
        CONFIG.REQUEST_TIMEOUT_MS,
    );

    try {
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (response.status === 425) {
            throw new Error("Time too early for Drand");
        }
        if (!response.ok) {
            throw new Error(`Drand returned status: ${response.status}`);
        }
        return response.json();
    } catch (error) {
        clearTimeout(timeoutId);
        if (error instanceof Error && error.name === "AbortError") {
            throw new Error("Drand API Timeout");
        }
        throw error;
    }
}

function combineRandomness(nistValue: string, drandValue: string): string {
    return nistValue + drandValue;
}

function validateParams(c: Context): {
    timestamp: string;
    num: number;
    min: number;
    max: number;
} {
    const timestamp = c.req.param("timestamp") as string;
    if (!timestamp) {
        throw new Error("Missing timestamp parameter.");
    }

    const num = parseInt(c.req.query("num") || String(CONFIG.DEFAULT_NUM));
    const min = parseFloat(c.req.query("min") || String(CONFIG.DEFAULT_MIN));
    const max = parseFloat(c.req.query("max") || String(CONFIG.DEFAULT_MAX));

    if (!isNumericValid(min, max, num)) {
        throw new Error("Invalid range parameters");
    }

    return { timestamp, num, min, max };
}

const app = new Hono();

app.onError((err, c) => {
    console.log("捕获到错误：", err);

    const message = err instanceof Error
        ? err.message
        : "Internal Server Error";
    let errorCode: string = ERROR_CODE.INTERNAL_ERROR;
    let status: StatusCode = 500 as StatusCode;

    let errorResponse: ErrorResponse = {
        error: message,
        errorCode: errorCode,
        timestamp: new Date().toISOString(),
    };

    if (message === "Pulse Not Available.") {
        errorCode = ERROR_CODE.NIST_PULSE_NOT_AVAILABLE;
        status = 404 as StatusCode;
        errorResponse = {
            error: "NIST pulse not available for this timestamp yet",
            errorCode,
            timestamp: c.req.param("timestamp") || "",
            suggestion: "Try a timestamp further in the past",
        };
    } else if (message === "Time too early for Drand") {
        errorCode = ERROR_CODE.DRAND_TOO_EARLY;
        status = 400 as StatusCode;
        errorResponse = {
            error: "Timestamp is too early for Drand",
            errorCode,
            timestamp: normalizeTimestamp(c.req.param("timestamp")) || "",
            genesisTime: CONFIG.GENESIS_TIME,
        };
    } else if (message.startsWith("Invalid range")) {
        errorCode = ERROR_CODE.INVALID_PARAMETERS;
        status = 400 as StatusCode;
        errorResponse = {
            error: message,
            errorCode,
            validRanges: {
                num: "1-1000",
                min: "Any number less than max",
                max: "Any number greater than min",
            },
        };
    } else if (message === "NIST API Timeout") {
        errorCode = ERROR_CODE.NIST_API_TIMEOUT;
        status = 504 as StatusCode;
        errorResponse = {
            error: "NIST API request timeout",
            errorCode,
            timestamp: c.req.param("timestamp") || "",
            suggestion: "Please try again later",
        };
    } else if (message === "Drand API Timeout") {
        errorCode = ERROR_CODE.DRAND_API_TIMEOUT;
        status = 504 as StatusCode;
        errorResponse = {
            error: "Drand API request timeout",
            errorCode,
            timestamp: c.req.param("timestamp") || "",
            suggestion: "Please try again later",
        };
    } else if (message === "Invalid NIST response") {
        errorCode = ERROR_CODE.INVALID_NIST_RESPONSE;
        status = 502 as StatusCode;
        errorResponse = {
            error: "Invalid response received from NIST API",
            errorCode,
            timestamp: c.req.param("timestamp") || "",
            suggestion: "Please check NIST service status or try again later",
        };
    } else if (message.startsWith("NIST returned status")) {
        errorCode = ERROR_CODE.INTERNAL_ERROR;
        // 尝试解析 "NIST returned status: XXX"
        // 如果无法解析就用 500
        status = (parseInt(message.split(": ")[1]) || 500) as StatusCode;
        errorResponse = {
            error: `Error from NIST service: ${message}`,
            errorCode,
            timestamp: c.req.param("timestamp") || "",
        };
    } else if (message.startsWith("Drand returned status")) {
        errorCode = ERROR_CODE.INTERNAL_ERROR;
        status = (parseInt(message.split(": ")[1]) || 500) as StatusCode;
        errorResponse = {
            error: `Error from Drand service: ${message}`,
            errorCode,
            timestamp: c.req.param("timestamp") || "",
        };
    }

    return c.json(errorResponse, status);
});

app.get("/", (c) => {
    const description = `
# Random Number Generator API

This API generates random numbers using a combination of randomness from NIST (National Institute of Standards and Technology) and DRAND (Distributed Randomness Beacon). It uses the Mersenne Twister (MT19937) algorithm seeded with combined values from these sources to produce pseudo-random numbers.

## How it works:

1. **Randomness Sources:**  The API fetches random values from:
    - **NIST Beacon:** A public randomness beacon provided by NIST, offering unpredictable and verifiable random bits.
    - **DRAND:** A distributed cryptographic randomness beacon, ensuring decentralized and robust randomness.

2. **Combining Randomness:** The API retrieves the latest or time-specific pulses from both NIST and DRAND. It combines the 'outputValue' from NIST and 'randomness' from DRAND to create a seed.

3. **Mersenne Twister (MT19937):** The combined seed is then used to initialize the MT19937 pseudo-random number generator. MT19937 is a fast and widely-used algorithm for generating high-quality pseudo-random numbers.

4. **Generating Random Numbers:**  Using the seeded MT19937 generator, the API generates the requested number of random integers within the specified range (min and max).

## Endpoints:

- **GET /random/:timestamp**: Generates random numbers for a given timestamp. You can specify query parameters: \`num\` (count), \`min\`, and \`max\`.
- **GET /nist/:timestamp**: Returns raw randomness data from NIST for a given timestamp.
- **GET /drand/:timestamp**: Returns raw randomness data from DRAND for a given timestamp.
- **GET /details**: Provides detailed information about the API, including how it works and the endpoints.
- **GET /**:  This description.

For more details, see /details.
    `;
    return c.text(description.trim());
});

app.get("/details", (c) => {
    const code = `
function combineRandomness(nistValue: string, drandValue: string): string {
    return nistValue + drandValue;
}
class MT19937 {
    private readonly N = 624;
    private readonly M = 397;
    private readonly MATRIX_A = 0x9908b0df;
    private readonly UPPER_MASK = 0x80000000;
    private readonly LOWER_MASK = 0x7fffffff;

    private mt: number[];
    private mti: number;

    constructor() {
        this.mt = new Array(this.N);
        this.mti = this.N + 1;
    }

    async initWithSeed(seed: string) {
        const hashBuffer = await crypto.subtle.digest(
            "SHA-512",
            new TextEncoder().encode(seed),
        );
        this.init_by_array(Array.from(new Uint32Array(hashBuffer)));
    }

    private init_by_array(initKey: number[]) {
        this.init_genrand(19650218);
        let i = 1;
        let j = 0;
        for (let k = Math.max(this.N, initKey.length); k; k--) {
            this.mt[i] = (this.mt[i] ^
                ((this.mt[i - 1] ^ (this.mt[i - 1] >>> 30)) * 1664525)) +
                initKey[j] +
                j;
            this.mt[i] >>>= 0;
            i++;
            j++;
            if (i >= this.N) {
                this.mt[0] = this.mt[this.N - 1];
                i = 1;
            }
            if (j >= initKey.length) j = 0;
        }
        for (let k = this.N - 1; k; k--) {
            this.mt[i] = (this.mt[i] ^
                ((this.mt[i - 1] ^ (this.mt[i - 1] >>> 30)) * 1566083941)) -
                i;
            this.mt[i] >>>= 0;
            i++;
            if (i >= this.N) {
                this.mt[0] = this.mt[this.N - 1];
                i = 1;
            }
        }
        this.mt[0] = 0x80000000;
    }

    private init_genrand(s: number) {
        this.mt[0] = s >>> 0;
        for (this.mti = 1; this.mti < this.N; this.mti++) {
            this.mt[this.mti] = 1812433253 *
                (this.mt[this.mti - 1] ^ (this.mt[this.mti - 1] >>> 30)) +
                this.mti;
            this.mt[this.mti] >>>= 0;
        }
    }

    next(): number {
        let y: number;
        const mag01 = [0x0, this.MATRIX_A];

        if (this.mti >= this.N) {
            let kk: number;

            for (kk = 0; kk < this.N - this.M; kk++) {
                y = (this.mt[kk] & this.UPPER_MASK) |
                    (this.mt[kk + 1] & this.LOWER_MASK);
                this.mt[kk] = this.mt[kk + this.M] ^ (y >>> 1) ^ mag01[y & 0x1];
            }
            for (; kk < this.N - 1; kk++) {
                y = (this.mt[kk] & this.UPPER_MASK) |
                    (this.mt[kk + 1] & this.LOWER_MASK);
                this.mt[kk] = this.mt[kk + (this.M - this.N)] ^ (y >>> 1) ^
                    mag01[y & 0x1];
            }
            y = (this.mt[this.N - 1] & this.UPPER_MASK) |
                (this.mt[0] & this.LOWER_MASK);
            this.mt[this.N - 1] = this.mt[this.M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

            this.mti = 0;
        }

        y = this.mt[this.mti++];

        y ^= y >>> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >>> 18;

        return y >>> 0;
    }

    generateNumbers(count: number, min: number, max: number): number[] {
        const range = max - min;
        return Array.from({ length: count }, () => {
            const fraction = this.next() / 0x100000000;
            return Math.floor(fraction * range + min);
        });
    }
}
`;
    return c.text(code);
});

app.get("/random/:timestamp", async (c) => {
    // 这里会先做参数校验，如果校验失败，就会抛出 "Invalid range parameters" 的错误
    // 然后会被 onError 捕获
    const { timestamp, num, min, max } = validateParams(c);

    const normalizedTimestamp = normalizeToNearestPeriod(timestamp);

    const [nistData, drandData] = await Promise.all([
        fetchNistData(normalizedTimestamp),
        fetchDrandData(normalizedTimestamp),
    ]);

    if (!nistData.pulse?.outputValue) {
        throw new Error("Invalid NIST response");
    }

    const combinedValue = combineRandomness(
        nistData.pulse.outputValue,
        drandData.randomness,
    );

    const mt = new MT19937();
    await mt.initWithSeed(combinedValue);
    const numbers = mt.generateNumbers(num, min, max);

    const response: RandomResponse = {
        timestamp: normalizedTimestamp,
        numbers,
        nistValue: nistData.pulse.outputValue,
        drandValue: drandData.randomness,
        combinedValue,
    };

    return c.json(response);
});

app.get("/nist/:timestamp", async (c) => {
    const timestamp = c.req.param("timestamp") as string;
    if (!timestamp) {
        return c.json(
            {
                error: "Missing timestamp parameter",
                errorCode: ERROR_CODE.MISSING_PARAMETER,
            } as ErrorResponse,
            400,
        );
    }
    const data = await fetchNistData(timestamp);
    return c.json(data);
});

app.get("/drand/:timestamp", async (c) => {
    const timestamp = c.req.param("timestamp") as string;
    if (!timestamp) {
        return c.json(
            {
                error: "Missing timestamp parameter",
                errorCode: ERROR_CODE.MISSING_PARAMETER,
            } as ErrorResponse,
            400,
        );
    }
    const data = await fetchDrandData(timestamp);
    return c.json(data);
});

Deno.serve(app.fetch);
