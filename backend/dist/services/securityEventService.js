import { randomUUID, } from "node:crypto";
export function createSecurityEvent(input) {
    return {
        id: randomUUID(),
        type: input.type,
        content: input.content,
        metadata: {
            timestamp: input.metadata?.timestamp ??
                new Date().toISOString(),
            source: input.metadata?.source ??
                "user",
            ipAddress: input.metadata?.ipAddress,
            deviceId: input.metadata?.deviceId,
            userAgent: input.metadata?.userAgent,
            location: input.metadata?.location,
            accountId: input.metadata?.accountId,
            sessionId: input.metadata?.sessionId,
            transactionId: input.metadata?.transactionId,
            amount: input.metadata?.amount,
            currency: input.metadata?.currency,
        },
    };
}
//# sourceMappingURL=securityEventService.js.map