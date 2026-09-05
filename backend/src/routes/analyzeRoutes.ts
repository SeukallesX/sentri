import {
  Router,
} from "express";

import {
  analyzeMessage,
} from "../services/scamAnalyzer.js";

import {
  createSecurityEvent,
} from "../services/securityEventService.js";

import {
  saveScan,
} from "../services/scanService.js";

import type {
  SecurityEventReference,
} from "../types/analysis.js";

const router =
  Router();

router.post(
  "/",
  (
    req,
    res,
  ) => {
    try {
      const message =
        typeof req.body?.message ===
        "string"
          ? req.body.message.trim()
          : "";

      if (!message) {
        return res
          .status(400)
          .json({
            error:
              "A message is required for analysis.",
          });
      }

      if (
        message.length >
        10000
      ) {
        return res
          .status(400)
          .json({
            error:
              "The message is too long.",
          });
      }

      /*
       * ---------------------------------------
       * 1. CREATE SECURITY EVENT
       * ---------------------------------------
       */

      const securityEvent =
        createSecurityEvent({
          type:
            "message",

          content:
            message,

          metadata: {
            source:
              "user",
          },
        });

      /*
       * ---------------------------------------
       * 2. CREATE EVENT REFERENCE
       * ---------------------------------------
       */

      const eventReference:
        SecurityEventReference = {
          id:
            securityEvent.id,

          type:
            securityEvent.type,

          timestamp:
            securityEvent
              .metadata
              .timestamp,

          source:
            securityEvent
              .metadata
              .source,
        };

      /*
       * ---------------------------------------
       * 3. RULE-X ANALYSIS
       * ---------------------------------------
       */

      const result =
        analyzeMessage(
          securityEvent.content,
        );

      /*
       * ---------------------------------------
       * 4. COMPLETE RESULT WITH EVENT
       * ---------------------------------------
       */

      const resultWithEvent = {
        ...result,

        event:
          eventReference,
      };

      /*
       * ---------------------------------------
       * 5. SAVE SCAN
       * ---------------------------------------
       */

      saveScan(
        "Message",

        securityEvent.content,

        resultWithEvent,

        eventReference,
      );

      /*
       * ---------------------------------------
       * 6. API RESPONSE
       * ---------------------------------------
       */

      return res
        .status(200)
        .json(
          resultWithEvent,
        );
    } catch (
      error
    ) {
      console.error(
        "Message analysis failed:",
        error,
      );

      return res
        .status(500)
        .json({
          error:
            "Unable to analyze the message.",
        });
    }
  },
);

export default router;